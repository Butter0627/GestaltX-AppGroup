#!/usr/bin/env bash
# Build GestaltX and package an ad-hoc signed IPA with the entitlements of the
# app and its share extension embedded. Re-signing tools such as AltStore and
# SideStore read the entitlements from the existing signature to decide which
# App Groups to register, so an unsigned IPA ends up without an App Group.
#
# Usage: .github/scripts/build-ipa.sh [output-dir]   (default: build/ipa)
#
# Set BUILD_DATE (YYYY-MM-DD) to write it to GestaltX/BuildDate.txt, which the
# About page shows. In GitHub Actions, `version` and `ipa` are written to
# GITHUB_OUTPUT.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="$(mkdir -p "${1:-$root/build/ipa}" && cd "${1:-$root/build/ipa}" && pwd)"
cd "$root"

# Every target must share one marketing version
version="$(sed -n 's/^[[:space:]]*MARKETING_VERSION = \(.*\);/\1/p' GestaltX.xcodeproj/project.pbxproj | sort -u)"
if [[ -z "$version" || "$(wc -l <<< "$version")" -ne 1 ]]; then
  echo "Error: expected one MARKETING_VERSION, found: ${version:-none}" >&2
  exit 1
fi
echo "==> Building GestaltX $version"

if [[ -n "${BUILD_DATE:-}" ]]; then
  printf '%s' "$BUILD_DATE" > GestaltX/BuildDate.txt
fi

# Locale JSON files must be compiled into the catalog used by both targets.
if [[ -f scripts/generate_localization.py ]]; then
  python3 scripts/generate_localization.py
fi

# Building the app target also builds the embedded share extension
xcodebuild -quiet \
  -project GestaltX.xcodeproj \
  -target GestaltX \
  -configuration Release \
  -sdk iphoneos \
  SYMROOT="$root/build" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  DEVELOPMENT_TEAM="" \
  build

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/Payload" "$out"
cp -R "$root/build/Release-iphoneos/GestaltX.app" "$stage/Payload/"
app="$stage/Payload/GestaltX.app"
appex="$app/PlugIns/GestaltXShare.appex"

# ==================== 建立偽造描述檔以利側載工具識別 App Group ====================
fake_team_id="1234567890"

generate_fake_provision() {
  local bundle_id="$1"
  local entitlements_file="$2"
  local target_dir="$3"
  local group_ids
  
  group_ids=$(plutil -extract "com.apple.security.application-groups" raw -expect array "$entitlements_file" 2>/dev/null || echo "")
  
  local temp_plist="$(mktemp)"
  cat <<END > "$temp_plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://apple.com">
<plist version="1.0">
<dict>
    <key>AppIDName</key>
    <string>GestaltX CI Build</string>
    <key>ApplicationIdentifierPrefix</key>
    <array>
        <string>${fake_team_id}</string>
    </array>
    <key>Entitlements</key>
    <dict>
        <key>application-identifier</key>
        <string>${fake_team_id}.${bundle_id}</string>
        <key>com.apple.developer.team-identifier</key>
        <string>${fake_team_id}</string>
        <key>get-task-allow</key>
        <true/>
    </dict>
    <key>TeamIdentifier</key>
    <array>
        <string>${fake_team_id}</string>
    </array>
    <key>TimeToLive</key>
    <integer>365</integer>
</dict>
</plist>
END

  if [[ -n "$group_ids" ]]; then
    plutil -insert "Entitlements.com.apple.security.application-groups" -xml "$(plutil -extract "com.apple.security.application-groups" xml1 "$entitlements_file" -o -)" "$temp_plist" 2>/dev/null || true
  fi

  cp "$temp_plist" "$target_dir/embedded.mobileprovision"
  rm -f "$temp_plist"
}

echo "==> Injecting fake mobileprovisions for sideload tools"
app_bundle_id=$(defaults read "$app/Info.plist" CFBundleIdentifier)
generate_fake_provision "$app_bundle_id" "GestaltX/GestaltX.entitlements" "$app"

if [[ -d "$appex" ]]; then
  appex_bundle_id=$(defaults read "$appex/Info.plist" CFBundleIdentifier)
  generate_fake_provision "$appex_bundle_id" "ShareExtension/GestaltXShare.entitlements" "$appex"
fi
# ==============================================================================

echo "==> Signing with entitlements"
# Sign nested code from the inside out: frameworks and dylibs, then the
# extension, then the app
while IFS= read -r -d '' item; do
  codesign -f -s - "$item"
done < <(find "$app" -depth \( -name '*.framework' -o -name '*.dylib' \) -print0)

prepare_signed_entitlements() {
  local src="$1"
  local bundle_id="$2"
  local dest="$(mktemp)"
  cp "$src" "$dest"
  plutil -insert "application-identifier" -string "${fake_team_id}.${bundle_id}" "$dest" 2>/dev/null || true
  plutil -insert "com.apple.developer.team-identifier" -string "${fake_team_id}" "$dest" 2>/dev/null || true
  echo "$dest"
}

bundles=()
if [[ -d "$appex" ]]; then
  appex_ent=$(prepare_signed_entitlements "ShareExtension/GestaltXShare.entitlements" "$appex_bundle_id")
  codesign -f -s - --entitlements "$appex_ent" "$appex"
  rm -f "$appex_ent"
  bundles+=("$appex")
fi

app_ent=$(prepare_signed_entitlements "GestaltX/GestaltX.entitlements" "$app_bundle_id")
codesign -f -s - --entitlements "$app_ent" "$app"
rm -f "$app_ent"
bundles+=("$app")

# Check the actual embedded signature, not just the entitlement source files.
python3 - "${bundles[@]}" <<'VERIFY_ENTITLEMENTS'
import plistlib, subprocess, sys
common = None
for bundle in sys.argv[1:]:
    subprocess.run(["codesign", "--verify", "--strict", bundle], check=True)
    result = subprocess.run(["codesign", "-d", "--entitlements", "-", "--xml", bundle], capture_output=True, check=True)
    entitlements = plistlib.loads(result.stdout)
    groups = entitlements.get("com.apple.security.application-groups", [])
    if not isinstance(groups, list) or not groups or not all(isinstance(group, str) and group for group in groups):
        raise SystemExit("Missing usable App Group entitlements in a signed bundle")
    
    metadata = subprocess.run(["codesign", "-dvv", bundle], capture_output=True, text=True, check=True).stderr
    if "Signature=adhoc" not in metadata:
        raise SystemExit("Expected an ad-hoc signature")
        
    common = set(groups) if common is None else common.intersection(groups)
if not common:
    raise SystemExit("The app and share extension do not have a common App Group")
print("App and embedded extensions retain common App Groups with ad-hoc signatures.")
VERIFY_ENTITLEMENTS

ipa="$out/GestaltX_$version.ipa"
# Keep an existing package until the replacement is complete.
(cd "$stage" && zip -qry "$stage/GestaltX_$version.ipa" Payload)
mv -f "$stage/GestaltX_$version.ipa" "$ipa"
echo "==> Wrote $ipa"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "version=$version"
    echo "ipa=$ipa"
  } >> "$GITHUB_OUTPUT"
fi
