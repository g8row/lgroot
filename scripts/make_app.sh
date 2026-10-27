#!/bin/sh
# Build LGroot.app for macOS.
#
#   sh scripts/make_app.sh          -> dist/LGroot.app
#   sh scripts/make_app.sh --debug  -> debug build, for development
#
# Everything the app needs is inside the bundle: one executable, one icon, no
# frameworks to install and no runtime to download.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

profile=release
if [ "${1:-}" = "--debug" ]; then
	profile=debug
fi

if [ ! -f assets/AppIcon.icns ]; then
	echo "assets/AppIcon.icns is missing; run: python3 scripts/make_icon.py" >&2
fi

cargo build --profile "$profile"

app="dist/LGroot.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

cp "target/$profile/lgroot" "$app/Contents/MacOS/lgroot"
cp packaging/Info.plist "$app/Contents/Info.plist"
if [ -f assets/AppIcon.icns ]; then
	cp assets/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
fi

# Ad-hoc signing is enough for a locally built app, and it stops macOS from
# complaining that the bundle is damaged. It cannot be notarised without a
# Developer ID, so the first launch may still need a right-click -> Open if the
# bundle is ever moved to another Mac.
codesign --force --sign - "$app" >/dev/null 2>&1 || true

printf 'built %s (%s)\n' "$app" "$(du -sh "$app" | cut -f1)"
