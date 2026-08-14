#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ICON_SRC="$ROOT_DIR/assets/nauxlang.png"
DESKTOP_SRC="$ROOT_DIR/assets/naux.desktop"
MIME_SRC="$ROOT_DIR/assets/naux-mime.xml"

ICON_THEME_DIR="$HOME/.local/share/icons/hicolor"
ICON_DIR="$ICON_THEME_DIR/256x256/apps"
APP_DIR="$HOME/.local/share/applications"
MIME_DIR="$HOME/.local/share/mime/packages"

mkdir -p "$ICON_DIR" "$APP_DIR" "$MIME_DIR"

INDEX_FILE="$ICON_THEME_DIR/index.theme"
if [ ! -f "$INDEX_FILE" ]; then
  cat > "$INDEX_FILE" <<'EOF'
[Icon Theme]
Name=hicolor
Comment=Default icon theme
Directories=256x256/apps

[256x256/apps]
Size=256
Context=Applications
Type=Fixed
EOF
fi

cp "$ICON_SRC" "$ICON_DIR/nauxlang.png"
cp "$ICON_SRC" "$ICON_DIR/application-x-naux.png"
cp "$DESKTOP_SRC" "$APP_DIR/naux.desktop"
cp "$MIME_SRC" "$MIME_DIR/naux.xml"

if command -v update-mime-database >/dev/null 2>&1; then
  update-mime-database "$HOME/.local/share/mime"
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$HOME/.local/share/applications"
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache "$ICON_THEME_DIR"
fi

if command -v xdg-mime >/dev/null 2>&1; then
  xdg-mime default naux.desktop application/x-naux
fi

echo "Installed .nx association for current user."
