#!/bin/bash
# Vetryx Session Start Security Scan
# Runs automatically when Claude Code session starts

set -e

# Read hook input (JSON from stdin)
HOOK_INPUT=$(cat)

# Paths to scan
CLAUDE_DIR="$HOME/.claude"
INSTALL_DIR="$HOME/.local/bin"

# Find vetryx binary
find_vetryx() {
    # Check PATH first
    if command -v vetryx &> /dev/null; then
        echo "vetryx"
        return 0
    fi

    # Check common install locations
    local locations=(
        "$INSTALL_DIR/vetryx"
        "$HOME/.cargo/bin/vetryx"
        "/usr/local/bin/vetryx"
        "/opt/homebrew/bin/vetryx"
    )

    for loc in "${locations[@]}"; do
        if [ -x "$loc" ]; then
            echo "$loc"
            return 0
        fi
    done

    return 1
}

# Auto-install vetryx if not found
auto_install() {
    local repo="edimuj/vetryx"
    local os arch asset_name version download_url

    # Detect platform
    case "$(uname -s)" in
        Darwin) os="macos" ;;
        Linux) os="linux" ;;
        *) return 1 ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) return 1 ;;
    esac

    asset_name="vetryx-${os}-${arch}"

    # Get latest version
    version=$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null | \
        grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "")

    if [ -z "$version" ]; then
        return 1
    fi

    download_url="https://github.com/${repo}/releases/download/${version}/${asset_name}"

    # Download and install
    mkdir -p "$INSTALL_DIR"
    if curl -fsSL "$download_url" -o "${INSTALL_DIR}/vetryx" 2>/dev/null; then
        chmod +x "${INSTALL_DIR}/vetryx"
        echo "${INSTALL_DIR}/vetryx"
        return 0
    fi

    return 1
}

# Try to find or install vetryx
VETRYX=$(find_vetryx)

if [ -z "$VETRYX" ]; then
    # Try auto-install
    VETRYX=$(auto_install 2>/dev/null || echo "")

    if [ -z "$VETRYX" ]; then
        # Give helpful install message
        echo '{"systemMessage": "Vetryx CLI not found. Install with: curl -fsSL https://raw.githubusercontent.com/edimuj/vetryx/main/install.sh | bash"}'
        exit 0
    fi
fi

# Run scan on Claude directory (plugins, skills, hooks, configs)
# Uses --third-party-only to skip official Anthropic components
SCAN_OUTPUT=$($VETRYX scan "$CLAUDE_DIR" --platform claude-code --third-party-only --min-severity medium -f json 2>/dev/null || true)

# Parse results
TOTAL_FINDINGS=$(echo "$SCAN_OUTPUT" | jq -r '.results | map(.findings | length) | add // 0' 2>/dev/null || echo "0")
MAX_SEVERITY=$(echo "$SCAN_OUTPUT" | jq -r '.results | map(.findings[].severity) | unique | if any(. == "critical") then "critical" elif any(. == "high") then "high" elif any(. == "medium") then "medium" else "none" end' 2>/dev/null || echo "none")

# Only report if issues found
if [ "$TOTAL_FINDINGS" != "0" ] && [ "$TOTAL_FINDINGS" != "null" ]; then
    # Build summary
    CRITICAL=$(echo "$SCAN_OUTPUT" | jq '[.results[].findings[] | select(.severity == "critical")] | length' 2>/dev/null || echo "0")
    HIGH=$(echo "$SCAN_OUTPUT" | jq '[.results[].findings[] | select(.severity == "high")] | length' 2>/dev/null || echo "0")
    MEDIUM=$(echo "$SCAN_OUTPUT" | jq '[.results[].findings[] | select(.severity == "medium")] | length' 2>/dev/null || echo "0")

    # Format message based on severity
    if [ "$MAX_SEVERITY" = "critical" ]; then
        MESSAGE="SECURITY ALERT: Found $CRITICAL critical, $HIGH high, $MEDIUM medium issue(s) in plugins/skills. Run /vetryx:scan for AI-powered analysis."
    elif [ "$MAX_SEVERITY" = "high" ]; then
        MESSAGE="Security Warning: Found $HIGH high, $MEDIUM medium issue(s) in plugins/skills. Run /vetryx:scan to review."
    else
        MESSAGE="Security Notice: Found $MEDIUM medium issue(s) in plugins/skills. Run /vetryx:scan for details."
    fi

    # Output for Claude Code
    echo "{\"systemMessage\": \"$MESSAGE\"}"
fi

exit 0
