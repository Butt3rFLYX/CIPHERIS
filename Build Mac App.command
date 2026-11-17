#!/bin/bash
# Double click in Finder: builds CIPHERIS.app and shows it in Finder.
cd "$(dirname "$0")" || exit 1
[ -x "$HOME/.cargo/bin/cargo" ] && export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust is not installed yet. Run this once in Terminal:"
  echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  read -r -p "Press Enter to close."
  exit 1
fi
if packaging/macos/build-app.sh; then
  open -R dist/CIPHERIS.app
else
  read -r -p "Build failed. Press Enter to close."
fi
