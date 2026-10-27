#!/bin/sh
# Build LGroot.app for macOS.
#
#   sh scripts/make_app.sh          -> dist/LGroot.app
#   sh scripts/make_app.sh --debug  -> debug build, for development
#
# Set LGROOT_BIN to bundle an executable that is already built (CI uses this
# for the universal binary) instead of running cargo.
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

bin=${LGROOT_BIN:-}
if [ -z "$bin" ]; then
	cargo build --profile "$profile"
	bin="target/$profile/lgroot"
fi

app="dist/LGroot.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

cp "$bin" "$app/Contents/MacOS/lgroot"
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
