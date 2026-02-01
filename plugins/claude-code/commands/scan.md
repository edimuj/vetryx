# /vetryx:scan

Run a security scan on Claude Code plugins, MCPs, and configurations.

## Usage

```
/vetryx:scan [path]
```

## Examples

- `/vetryx:scan` - Scan all installed plugins
- `/vetryx:scan ~/.claude/plugins/cache/some-plugin` - Scan specific plugin
- `/vetryx:scan --third-party-only` - Only scan untrusted plugins

## What It Detects

- **Code Execution**: eval(), exec(), dangerous functions
- **Shell Injection**: Command execution, subprocess calls
- **Data Exfiltration**: Webhooks, external POST requests
- **Credential Access**: SSH keys, API tokens, env files
- **Prompt Injection**: Instruction override attempts
- **Obfuscation**: Base64, hex, unicode encoding

## Instructions

When the user runs this command:

1. Execute `vetryx scan` on the specified path (default: `~/.claude/plugins`)
2. Use `--third-party-only` flag to skip official Anthropic plugins
3. Report findings with severity levels (Critical, High, Medium, Low)
4. For any Critical or High findings, recommend immediate review
5. Provide remediation guidance for each finding

Run the scan with:
```bash
vetryx scan "${1:-$HOME/.claude/plugins}" --third-party-only -f cli
```
