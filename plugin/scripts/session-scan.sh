#!/bin/bash
# Vetryx Session Start Security Scan
# Runs automatically when Claude Code session starts

set -e

# Read hook input (JSON from stdin)
HOOK_INPUT=$(cat)

# Paths to scan
PLUGIN_DIR="$HOME/.claude/plugins"
MCP_CONFIG="$HOME/.claude.json"

# Check if vetryx is installed
if ! command -v vetryx &> /dev/null; then
    # Try common install locations
    if [ -f "$HOME/.cargo/bin/vetryx" ]; then
        VETRYX="$HOME/.cargo/bin/vetryx"
    elif [ -f "/usr/local/bin/vetryx" ]; then
        VETRYX="/usr/local/bin/vetryx"
    else
        echo '{"systemMessage": "Vetryx not found. Install with: cargo install vetryx"}'
        exit 0
    fi
else
    VETRYX="vetryx"
fi

# Run scan on third-party plugins only (skip official ones)
SCAN_OUTPUT=$($VETRYX scan "$PLUGIN_DIR" --third-party-only --min-severity medium -f json 2>/dev/null || true)

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
        MESSAGE="SECURITY ALERT: Found $CRITICAL critical, $HIGH high, $MEDIUM medium issue(s) in third-party plugins. Run 'vetryx scan ~/.claude/plugins' for details."
    elif [ "$MAX_SEVERITY" = "high" ]; then
        MESSAGE="Security Warning: Found $HIGH high, $MEDIUM medium issue(s) in third-party plugins. Review with 'vetryx scan ~/.claude/plugins'."
    else
        MESSAGE="Security Notice: Found $MEDIUM medium issue(s) in third-party plugins."
    fi

    # Output for Claude Code
    echo "{\"systemMessage\": \"$MESSAGE\"}"
fi

exit 0
