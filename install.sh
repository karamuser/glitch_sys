#!/bin/bash
# Glitch Sys Installer
set -e

echo "=== Glitch Sys Installer ==="

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

echo "OS: $OS"
echo "Arch: $ARCH"

# Install dependencies
if [ "$OS" = "Linux" ]; then
    if command -v pkg &> /dev/null; then
        echo "Termux detected"
        pkg update -y
        pkg install -y python git
    elif command -v apt &> /dev/null; then
        echo "Debian/Ubuntu detected"
        sudo apt update
        sudo apt install -y python3 python3-pip git
    elif command -v pacman &> /dev/null; then
        echo "Arch detected"
        sudo pacman -Sy --noconfirm python python-pip git
    elif command -v dnf &> /dev/null; then
        echo "Fedora detected"
        sudo dnf install -y python3 python3-pip git
    fi
fi

# Clone repo
if [ ! -d "$HOME/glitch_sys" ]; then
    git clone https://github.com/karamuser/glitch_sys.git "$HOME/glitch_sys"
fi

cd "$HOME/glitch_sys/src"

# Install Python deps
# pip upgrade removed (Termux restriction)
pip install rich

# Optional: install kivy for GUI (skip on Termux/Android)
if [ "$OS" = "Linux" ] && [ ! -d "/data/data/com.termux" ]; then
    read -p "Install GUI (Kivy)? [y/N]: " install_gui
    if [ "$install_gui" = "y" ] || [ "$install_gui" = "Y" ]; then
        pip install kivy
    fi
fi

echo ""
echo "=== Installation Complete ==="
echo "Run: cd $HOME/glitch_sys/src && python glitch_sys.py start"
