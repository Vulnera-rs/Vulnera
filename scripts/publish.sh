#!/usr/bin/env bash
#
# Vulnera CLI Release Publisher
# Publishes built binaries to the public releases repository
#
# Usage:
#   ./scripts/publish.sh <version> [--prerelease] [--draft]
#
# Prerequisites:
#   - GitHub CLI (gh) authenticated with access to k5602/vulnera-releases
#   - Built distribution files in dist/ directory
#
# Example:
#   ./scripts/publish.sh v1.0.0
#   ./scripts/publish.sh v1.1.0-beta.1 --prerelease
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RELEASES_REPO="k5602/vulnera-releases"
DIST_DIR="dist"

# Parse arguments
VERSION=""
IS_PRERELEASE=false
IS_DRAFT=false

while [[ $# -gt 0 ]]; do
    case $1 in
        v*)
            VERSION="$1"
            shift
            ;;
        --prerelease)
            IS_PRERELEASE=true
            shift
            ;;
        --draft)
            IS_DRAFT=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 <version> [--prerelease] [--draft]"
            echo ""
            echo "Arguments:"
            echo "  <version>     Version tag (e.g., v1.0.0)"
            echo ""
            echo "Options:"
            echo "  --prerelease  Mark as pre-release"
            echo "  --draft       Create as draft release"
            echo ""
            echo "Prerequisites:"
            echo "  - GitHub CLI (gh) authenticated"
            echo "  - Distribution files in dist/"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Validate version
if [[ -z "$VERSION" ]]; then
    # Try to get from Cargo.toml
    CARGO_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
    VERSION="v${CARGO_VERSION}"
    echo -e "${YELLOW}No version specified, using v${CARGO_VERSION} from Cargo.toml${NC}"
fi

# Ensure version starts with 'v'
if [[ ! "$VERSION" =~ ^v ]]; then
    VERSION="v${VERSION}"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Vulnera CLI Release Publisher"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo -e "Version:      ${BLUE}${VERSION}${NC}"
echo -e "Repository:   ${BLUE}${RELEASES_REPO}${NC}"
echo -e "Pre-release:  ${BLUE}${IS_PRERELEASE}${NC}"
echo -e "Draft:        ${BLUE}${IS_DRAFT}${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

# Check gh CLI
if ! command -v gh &> /dev/null; then
    echo -e "${RED}Error: GitHub CLI (gh) not found${NC}"
    echo "Install from: https://cli.github.com/"
    exit 1
fi
echo -e "${GREEN}  ✓ GitHub CLI found${NC}"

# Check gh authentication
if ! gh auth status &>/dev/null; then
    echo -e "${RED}Error: GitHub CLI not authenticated${NC}"
    echo "Run: gh auth login"
    exit 1
fi
echo -e "${GREEN}  ✓ GitHub CLI authenticated${NC}"

# Check dist directory
if [[ ! -d "$DIST_DIR" ]]; then
    echo -e "${RED}Error: Distribution directory not found: $DIST_DIR${NC}"
    echo "Run: ./scripts/distribute.sh --all"
    exit 1
fi

# Find release files
RELEASE_FILES=()
for f in "$DIST_DIR"/*.tar.gz "$DIST_DIR"/*.zip; do
    if [[ -f "$f" ]]; then
        RELEASE_FILES+=("$f")
    fi
done

if [[ ${#RELEASE_FILES[@]} -eq 0 ]]; then
    echo -e "${RED}Error: No release files found in $DIST_DIR${NC}"
    echo "Run: ./scripts/distribute.sh --all"
    exit 1
fi
echo -e "${GREEN}  ✓ Found ${#RELEASE_FILES[@]} release file(s)${NC}"

# Check checksums
if [[ ! -f "$DIST_DIR/checksums.sha256" ]]; then
    echo -e "${YELLOW}  ⚠ No checksums.sha256 found, will skip checksum upload${NC}"
fi

echo ""

# Generate release notes
RELEASE_NOTES=$(cat <<EOF
# Vulnera CLI ${VERSION}

## Installation

### Quick Install (Recommended)

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/${RELEASES_REPO}/main/install.sh | sh
\`\`\`

### Manual Download

Download the appropriate binary for your platform:

| Platform | Architecture | Download |
|----------|--------------|----------|
| Linux | x86_64 | [vulnera-${VERSION}-x86_64-unknown-linux-gnu.tar.gz](https://github.com/${RELEASES_REPO}/releases/download/${VERSION}/vulnera-${VERSION}-x86_64-unknown-linux-gnu.tar.gz) |
| Linux (musl) | x86_64 | [vulnera-${VERSION}-x86_64-unknown-linux-musl.tar.gz](https://github.com/${RELEASES_REPO}/releases/download/${VERSION}/vulnera-${VERSION}-x86_64-unknown-linux-musl.tar.gz) |
| Linux | ARM64 | [vulnera-${VERSION}-aarch64-unknown-linux-gnu.tar.gz](https://github.com/${RELEASES_REPO}/releases/download/${VERSION}/vulnera-${VERSION}-aarch64-unknown-linux-gnu.tar.gz) |
| macOS | Intel | [vulnera-${VERSION}-x86_64-apple-darwin.tar.gz](https://github.com/${RELEASES_REPO}/releases/download/${VERSION}/vulnera-${VERSION}-x86_64-apple-darwin.tar.gz) |
| macOS | Apple Silicon | [vulnera-${VERSION}-aarch64-apple-darwin.tar.gz](https://github.com/${RELEASES_REPO}/releases/download/${VERSION}/vulnera-${VERSION}-aarch64-apple-darwin.tar.gz) |
| Windows | x86_64 | [vulnera-${VERSION}-x86_64-pc-windows-msvc.zip](https://github.com/${RELEASES_REPO}/releases/download/${VERSION}/vulnera-${VERSION}-x86_64-pc-windows-msvc.zip) |

### Verify Checksum

After downloading, verify the checksum:

\`\`\`bash
# Download checksums
curl -LO https://github.com/${RELEASES_REPO}/releases/download/${VERSION}/checksums.sha256

# Verify (Linux)
sha256sum -c checksums.sha256 --ignore-missing

# Verify (macOS)
shasum -a 256 -c checksums.sha256 --ignore-missing
\`\`\`

## What's New

See [CHANGELOG.md](https://github.com/k5602/vulnera/blob/main/CHANGELOG.md) for details.

## Documentation

- [Quick Start Guide](https://github.com/k5602/vulnera/blob/main/docs/QUICK_START.md)
- [CLI Guide](https://github.com/k5602/vulnera/blob/main/docs/CLI_GUIDE.md)

## Support

- Report issues: [GitHub Issues](https://github.com/k5602/vulnera/issues)
- Get API key: https://api.vulnera.studio/
EOF
)

# Save release notes to temp file
NOTES_FILE=$(mktemp)
echo "$RELEASE_NOTES" > "$NOTES_FILE"

echo -e "${YELLOW}Creating release ${VERSION}...${NC}"

# Build gh release command
GH_ARGS=("release" "create" "$VERSION")
GH_ARGS+=("--repo" "$RELEASES_REPO")
GH_ARGS+=("--title" "Vulnera CLI ${VERSION}")
GH_ARGS+=("--notes-file" "$NOTES_FILE")

if [[ "$IS_PRERELEASE" == true ]]; then
    GH_ARGS+=("--prerelease")
fi

if [[ "$IS_DRAFT" == true ]]; then
    GH_ARGS+=("--draft")
fi

# Add all release files
for f in "${RELEASE_FILES[@]}"; do
    GH_ARGS+=("$f")
done

# Add checksums if exists
if [[ -f "$DIST_DIR/checksums.sha256" ]]; then
    GH_ARGS+=("$DIST_DIR/checksums.sha256")
fi

# Check if release already exists
if gh release view "$VERSION" --repo "$RELEASES_REPO" &>/dev/null; then
    echo -e "${YELLOW}Release ${VERSION} already exists. Deleting and recreating...${NC}"
    gh release delete "$VERSION" --repo "$RELEASES_REPO" --yes || true
fi

# Create release
if gh "${GH_ARGS[@]}"; then
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Release ${VERSION} published successfully!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Release URL: https://github.com/${RELEASES_REPO}/releases/tag/${VERSION}"
    echo ""
    echo "Install command:"
    echo "  curl -fsSL https://raw.githubusercontent.com/${RELEASES_REPO}/main/install.sh | sh"
else
    echo -e "${RED}Failed to create release${NC}"
    rm -f "$NOTES_FILE"
    exit 1
fi

# Cleanup
rm -f "$NOTES_FILE"

echo ""
echo "Next steps:"
echo "  1. Verify the release: gh release view ${VERSION} --repo ${RELEASES_REPO}"
echo "  2. Test the installer: curl -fsSL https://raw.githubusercontent.com/${RELEASES_REPO}/main/install.sh | sh"
echo "  3. Announce the release"
