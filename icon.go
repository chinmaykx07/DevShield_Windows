// icon.go — Embeds assets/devshield.ico into the binary at compile time.
//
// PLACEMENT: This file belongs in the REPO ROOT (same directory as main.go),
// NOT inside assets/. All package main files must share one directory.
// The //go:embed path is relative to this file, so "assets/devshield.ico"
// resolves correctly from the root.
//
// HOW TO CREATE devshield.ico (place in assets/ before running go build):
//
//   Option A — Online (easiest):
//     1. Go to https://favicon.io/favicon-generator/
//     2. Type "DS" or upload any shield SVG
//     3. Download the .ico → rename to devshield.ico → place in assets/
//
//   Option B — PowerShell + ImageMagick (if you have a PNG):
//     winget install ImageMagick.ImageMagick
//     magick convert icon_256.png -define icon:auto-resize=256,64,48,32,16 assets\devshield.ico
//
//   Option C — Use the placeholder (builds fine, generic icon in tray):
//     The placeholder.ico committed to the repo is a minimal valid 16×16 icon.
//     Replace it with your real icon before v0.1 release.
//
// Build WILL FAIL with:
//   pattern assets/devshield.ico: no matching files found
// if the file is missing. That is intentional — never ship without an icon.

package main

import _ "embed"

//go:embed assets/devshield.ico
var trayIconData []byte
