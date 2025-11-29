#!/usr/bin/env sh
#
# Vulnera CLI Installer
# This script installs the Vulnera CLI on your system
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/k5602/vulnera-releases/main/install.sh | sh
#
# Options (via environment variables):
#   VULNERA_VERSION   - Specific version to install (default: latest)
#   VULNERA_INSTALL   - Installation directory (default: ~/.vulnera/bin)
#
# Supported Platforms:
#   - Linux (x86_64, aarch64)
#   - macOS (Intel, Apple Silicon)
#   - Windows (via WSL)
#

set -e

# Configuration
RELEASES_REPO="k5602/vulnera-releases"
BINARY_NAME="vulnera"
DEFAULT_INSTALL_DIR="$HOME/.vulnera/bin"

# Colors (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    NC=''
fi

# Print functions
info() {
    printf "${BLUE}info${NC}: %s\n" "$1"
}

success() {
    printf "${GREEN}success${NC}: %s\n" "$1"
}

warn() {
    printf "${YELLOW}warning${NC}: %s\n" "$1"
}

error() {
    printf "${RED}error${NC}: %s\n" "$1" >&2
}

# Banner
print_banner() {
    printf "\n"
    printf "${BLUE}${BOLD}"
    printf " ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██████╗  █████╗ \n"
    printf " ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔══██╗██╔══██╗\n"
    printf " ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██████╔╝███████║\n"
    printf " ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║\n"
    printf "  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗██║  ██║██║  ██║\n"
    printf "   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝\n"
    printf "${NC}"
    printf "\n"
    printf "           ${BOLD}Security Analysis Platform${NC}\n"
    printf "\n"
}

# Detect OS
detect_os() {
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$os" in
        linux)
            # Check for musl vs glibc
            if ldd --version 2>&1 | grep -qi musl; then
                echo "linux-musl"
            else
                echo "linux"
            fi
            ;;
        darwin)
            echo "darwin"
            ;;
        mingw*|msys*|cygwin*)
            echo "windows"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Detect architecture
detect_arch() {
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            echo "x86_64"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Get target triple
get_target() {
    os=$(detect_os)
    arch=$(detect_arch)
    
    case "$os" in
        linux)
            echo "${arch}-unknown-linux-gnu"
            ;;
        linux-musl)
            echo "${arch}-unknown-linux-musl"
            ;;
        darwin)
            echo "${arch}-apple-darwin"
            ;;
        windows)
            echo "${arch}-pc-windows-msvc"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Get latest version from GitHub
get_latest_version() {
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${RELEASES_REPO}/releases/latest" 2>/dev/null | \
            grep '"tag_name"' | \
            sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/'
    elif command -v wget > /dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${RELEASES_REPO}/releases/latest" 2>/dev/null | \
            grep '"tag_name"' | \
            sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/'
    else
        echo ""
    fi
}

# Download file
download() {
    url="$1"
    output="$2"
    
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget > /dev/null 2>&1; then
        wget -q "$url" -O "$output"
    else
        error "Neither curl nor wget found"
        exit 1
    fi
}

# Verify checksum
verify_checksum() {
    file="$1"
    checksums_file="$2"
    filename=$(basename "$file")
    
    if [ ! -f "$checksums_file" ]; then
        warn "Checksums file not found, skipping verification"
        return 0
    fi
    
    expected=$(grep "$filename" "$checksums_file" | awk '{print $1}')
    if [ -z "$expected" ]; then
        warn "No checksum found for $filename, skipping verification"
        return 0
    fi
    
    if command -v sha256sum > /dev/null 2>&1; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum > /dev/null 2>&1; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        warn "No checksum tool available, skipping verification"
        return 0
    fi
    
    if [ "$expected" = "$actual" ]; then
        success "Checksum verified"
        return 0
    else
        error "Checksum mismatch!"
        error "Expected: $expected"
        error "Actual:   $actual"
        return 1
    fi
}

# Extract archive
extract() {
    archive="$1"
    target="$2"
    
    case "$archive" in
        *.tar.gz|*.tgz)
            tar -xzf "$archive" -C "$target"
            ;;
        *.zip)
            if command -v unzip > /dev/null 2>&1; then
                unzip -q "$archive" -d "$target"
            else
                error "unzip not found, cannot extract .zip archive"
                exit 1
            fi
            ;;
        *)
            error "Unknown archive format: $archive"
            exit 1
            ;;
    esac
}

# Add to PATH instructions
print_path_instructions() {
    install_dir="$1"
    shell_name=$(basename "$SHELL")
    
    printf "\n"
    printf "${YELLOW}Add Vulnera to your PATH:${NC}\n"
    printf "\n"
    
    case "$shell_name" in
        bash)
            printf "  echo 'export PATH=\"%s:\$PATH\"' >> ~/.bashrc\n" "$install_dir"
            printf "  source ~/.bashrc\n"
            ;;
        zsh)
            printf "  echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc\n" "$install_dir"
            printf "  source ~/.zshrc\n"
            ;;
        fish)
            printf "  fish_add_path %s\n" "$install_dir"
            ;;
        *)
            printf "  Add %s to your PATH\n" "$install_dir"
            ;;
    esac
    
    printf "\n"
    printf "Or run directly:\n"
    printf "  %s/%s --version\n" "$install_dir" "$BINARY_NAME"
    printf "\n"
}

# Main installation
main() {
    print_banner
    
    info "Detecting platform..."
    
    # Detect platform
    target=$(get_target)
    if [ -z "$target" ]; then
        error "Unsupported platform: $(uname -s) $(uname -m)"
        exit 1
    fi
    
    info "Detected target: $target"
    
    # Get version
    version="${VULNERA_VERSION:-}"
    if [ -z "$version" ]; then
        info "Fetching latest version..."
        version=$(get_latest_version)
        if [ -z "$version" ]; then
            error "Could not determine latest version"
            error "Try specifying: VULNERA_VERSION=v1.0.0 $0"
            exit 1
        fi
    fi
    
    info "Installing Vulnera ${version}"
    
    # Set install directory
    install_dir="${VULNERA_INSTALL:-$DEFAULT_INSTALL_DIR}"
    
    # Create temp directory
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT
    
    # Determine archive extension
    case "$target" in
        *windows*)
            archive_ext="zip"
            binary_ext=".exe"
            ;;
        *)
            archive_ext="tar.gz"
            binary_ext=""
            ;;
    esac
    
    # Construct download URL
    archive_name="${BINARY_NAME}-${version}-${target}.${archive_ext}"
    download_url="https://github.com/${RELEASES_REPO}/releases/download/${version}/${archive_name}"
    checksums_url="https://github.com/${RELEASES_REPO}/releases/download/${version}/checksums.sha256"
    
    info "Downloading ${archive_name}..."
    download "$download_url" "$tmp_dir/$archive_name"
    
    info "Downloading checksums..."
    download "$checksums_url" "$tmp_dir/checksums.sha256" 2>/dev/null || true
    
    # Verify checksum
    info "Verifying checksum..."
    verify_checksum "$tmp_dir/$archive_name" "$tmp_dir/checksums.sha256"
    
    # Extract
    info "Extracting..."
    extract "$tmp_dir/$archive_name" "$tmp_dir"
    
    # Find binary
    binary_path=$(find "$tmp_dir" -name "${BINARY_NAME}${binary_ext}" -type f | head -n 1)
    if [ -z "$binary_path" ]; then
        error "Binary not found in archive"
        exit 1
    fi
    
    # Create install directory
    mkdir -p "$install_dir"
    
    # Install binary
    info "Installing to ${install_dir}..."
    cp "$binary_path" "${install_dir}/${BINARY_NAME}${binary_ext}"
    chmod +x "${install_dir}/${BINARY_NAME}${binary_ext}"
    
    # Success!
    printf "\n"
    printf "${GREEN}${BOLD}════════════════════════════════════════════════════════════════${NC}\n"
    printf "${GREEN}${BOLD}  Vulnera CLI ${version} installed successfully!${NC}\n"
    printf "${GREEN}${BOLD}════════════════════════════════════════════════════════════════${NC}\n"
    
    # Check if already in PATH
    if echo "$PATH" | grep -q "$install_dir"; then
        printf "\n"
        success "Vulnera is in your PATH"
        printf "\n"
        printf "Get started:\n"
        printf "  vulnera --help\n"
        printf "  vulnera auth login\n"
        printf "\n"
    else
        print_path_instructions "$install_dir"
    fi
    
    printf "Documentation: https://github.com/k5602/vulnera/blob/main/docs/CLI_GUIDE.md\n"
    printf "\n"
}

# Run main
main
