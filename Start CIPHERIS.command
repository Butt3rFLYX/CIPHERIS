#!/bin/bash
# Double click in Finder: builds CIPHERIS once (one or two minutes), then starts it.
cd "$(dirname "$0")" || exit 1
[ -x "$HOME/.cargo/bin/cargo" ] && export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust is not installed yet. Run this once in Terminal:"
  echo
  echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  echo
  echo "Then close this window and double click 'Start CIPHERIS' again."
  read -r -p "Press Enter to close."
  exit 1
fi
echo "Preparing CIPHERIS ..."
cargo build --release -p cipheris || { read -r -p "Build failed. Press Enter to close."; exit 1; }
exec ./target/release/cipheris
