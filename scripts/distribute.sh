#!/usr/bin/env bash
#
# Vulnera CLI Distribution Build Script
# Builds binaries for multiple platforms from the current host
#
# Usage:
#   ./scripts/distribute.sh [--target <target>] [--all] [--release]
#
# Options:
#   --target <target>  Build for specific target (e.g., x86_64-unknown-linux-gnu)
#   --all              Build for all supported targets (requires cross)
#   --release          Build release version (default)
#   --debug            Build debug version
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BINARY_NAME="vulnera"
DIST_DIR="dist"
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
    "x86_64-pc-windows-msvc"
)

# Parse arguments
BUILD_MODE="release"
SPECIFIC_TARGET=""
BUILD_ALL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            SPECIFIC_TARGET="$2"
            shift 2
            ;;
        --all)
            BUILD_ALL=true
            shift
            ;;
        --release)
            BUILD_MODE="release"
            shift
            ;;
        --debug)
            BUILD_MODE="debug"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--target <target>] [--all] [--release|--debug]"
            echo ""
            echo "Supported targets:"
            for t in "${TARGETS[@]}"; do
                echo "  - $t"
            done
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Get version from Cargo.toml
VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo -e "${BLUE}Building Vulnera CLI v${VERSION}${NC}"
echo ""

# Create dist directory
mkdir -p "$DIST_DIR"

# Detect current platform
detect_platform() {
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    
    case "$os" in
        linux)
            case "$arch" in
                x86_64) echo "x86_64-unknown-linux-gnu" ;;
                aarch64) echo "aarch64-unknown-linux-gnu" ;;
                *) echo "unknown" ;;
            esac
            ;;
        darwin)
            case "$arch" in
                x86_64) echo "x86_64-apple-darwin" ;;
                arm64) echo "aarch64-apple-darwin" ;;
                *) echo "unknown" ;;
            esac
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Check if cross is available
has_cross() {
    command -v cross &> /dev/null
}

# Check if target is installed
has_target() {
    rustup target list --installed | grep -q "^$1$"
}

# Build for a specific target
build_target() {
    local target=$1
    local current_platform
    current_platform=$(detect_platform)
    
    echo -e "${YELLOW}Building for ${target}...${NC}"
    
    local cargo_cmd="cargo"
    local build_flags=("--target" "$target" "--manifest-path" "vulnera-cli/Cargo.toml")
    
    if [[ "$BUILD_MODE" == "release" ]]; then
        build_flags+=("--release")
    fi
    
    # Determine if we need cross
    if [[ "$target" != "$current_platform" ]]; then
        if has_cross; then
            cargo_cmd="cross"
            echo -e "  Using cross for cross-compilation"
        elif ! has_target "$target"; then
            echo -e "${RED}  Target $target not installed and cross not available${NC}"
            echo -e "  Install with: rustup target add $target"
            echo -e "  Or install cross: cargo install cross"
            return 1
        fi
    fi
    
    # Build
    if ! $cargo_cmd build "${build_flags[@]}"; then
        echo -e "${RED}  Build failed for $target${NC}"
        return 1
    fi
    
    # Determine binary path and extension
    local binary_ext=""
    if [[ "$target" == *"windows"* ]]; then
        binary_ext=".exe"
    fi
    
    local src_binary="target/${target}/${BUILD_MODE}/${BINARY_NAME}${binary_ext}"
    
    if [[ ! -f "$src_binary" ]]; then
        echo -e "${RED}  Binary not found: $src_binary${NC}"
        return 1
    fi
    
    # Create archive
    local archive_name="${BINARY_NAME}-v${VERSION}-${target}"
    local archive_dir="${DIST_DIR}/${archive_name}"
    
    rm -rf "$archive_dir"
    mkdir -p "$archive_dir"
    
    # Copy binary
    cp "$src_binary" "$archive_dir/${BINARY_NAME}${binary_ext}"
    
    # Strip binary (reduces size significantly)
    if [[ "$target" != *"windows"* ]] && command -v strip &> /dev/null; then
        strip "$archive_dir/${BINARY_NAME}" 2>/dev/null || true
    fi
    
    # Copy additional files
    cp README.md "$archive_dir/" 2>/dev/null || true
    cp LICENSE "$archive_dir/" 2>/dev/null || true
    
    # Create archive
    cd "$DIST_DIR"
    if [[ "$target" == *"windows"* ]]; then
        if command -v zip &> /dev/null; then
            zip -r "${archive_name}.zip" "$archive_name"
            echo -e "${GREEN}  Created ${archive_name}.zip${NC}"
        else
            tar -czvf "${archive_name}.tar.gz" "$archive_name"
            echo -e "${GREEN}  Created ${archive_name}.tar.gz${NC}"
        fi
    else
        tar -czvf "${archive_name}.tar.gz" "$archive_name"
        echo -e "${GREEN}  Created ${archive_name}.tar.gz${NC}"
    fi
    cd ..
    
    # Cleanup temp directory
    rm -rf "$archive_dir"
    
    return 0
}

# Generate checksums
generate_checksums() {
    echo -e "${YELLOW}Generating checksums...${NC}"
    cd "$DIST_DIR"
    
    # Use sha256sum on Linux, shasum on macOS
    if command -v sha256sum &> /dev/null; then
        sha256sum *.tar.gz *.zip 2>/dev/null > checksums.sha256 || sha256sum *.tar.gz > checksums.sha256
    elif command -v shasum &> /dev/null; then
        shasum -a 256 *.tar.gz *.zip 2>/dev/null > checksums.sha256 || shasum -a 256 *.tar.gz > checksums.sha256
    else
        echo -e "${RED}  Neither sha256sum nor shasum found${NC}"
        cd ..
        return 1
    fi
    
    cd ..
    echo -e "${GREEN}  Created checksums.sha256${NC}"
}

# Main execution
main() {
    echo "════════════════════════════════════════════════════════════════"
    echo "  Vulnera CLI Distribution Builder"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    
    local current_platform
    current_platform=$(detect_platform)
    echo -e "Current platform: ${BLUE}${current_platform}${NC}"
    echo -e "Build mode: ${BLUE}${BUILD_MODE}${NC}"
    echo ""
    
    local targets_to_build=()
    local failed_targets=()
    
    if [[ -n "$SPECIFIC_TARGET" ]]; then
        targets_to_build=("$SPECIFIC_TARGET")
    elif [[ "$BUILD_ALL" == true ]]; then
        targets_to_build=("${TARGETS[@]}")
    else
        # Default: build for current platform only
        targets_to_build=("$current_platform")
    fi
    
    echo "Targets to build:"
    for t in "${targets_to_build[@]}"; do
        echo "  - $t"
    done
    echo ""
    
    # Build each target
    for target in "${targets_to_build[@]}"; do
        if build_target "$target"; then
            echo ""
        else
            failed_targets+=("$target")
            echo ""
        fi
    done
    
    # Generate checksums
    if ls "$DIST_DIR"/*.tar.gz &>/dev/null || ls "$DIST_DIR"/*.zip &>/dev/null; then
        generate_checksums
    fi
    
    # Summary
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  Build Summary"
    echo "════════════════════════════════════════════════════════════════"
    
    echo -e "\n${GREEN}Successfully built:${NC}"
    ls -la "$DIST_DIR"/*.tar.gz "$DIST_DIR"/*.zip 2>/dev/null || echo "  (none)"
    
    if [[ ${#failed_targets[@]} -gt 0 ]]; then
        echo -e "\n${RED}Failed targets:${NC}"
        for t in "${failed_targets[@]}"; do
            echo "  - $t"
        done
        exit 1
    fi
    
    echo ""
    echo -e "${GREEN}Distribution files ready in ${DIST_DIR}/${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Test the binaries"
    echo "  2. Run: ./scripts/publish.sh v${VERSION}"
}

main
