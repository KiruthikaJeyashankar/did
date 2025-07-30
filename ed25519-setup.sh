#!/bin/bash

echo "🔧 Setting up Python environment for DID document generation..."

# Create a virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip3 install --upgrade pip

# Install required packages
REQUIRED_PACKAGES=(
    base58
    cryptography
    jwcrypto
    requests
    pynacl
    jwcrypto
)

echo "📦 Installing required packages..."
for package in "${REQUIRED_PACKAGES[@]}"; do
    echo "Installing $package..."
    pip3 install "$package"
done

echo "✅ All packages installed successfully."
echo "👉 To activate the virtual environment later, run: source venv/bin/activate"
