# /vetryx:scan

Run a security scan on Claude Code plugins, skills, MCPs, and configurations.

**Runs as a subagent to keep your main conversation clean.**

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

**IMPORTANT: Always run this as a Task subagent to avoid polluting the main context.**

When the user runs this command:

1. Use the **Task tool** to spawn a subagent with the following configuration:
   - `subagent_type`: "general-purpose"
   - `description`: "Security scan with Vetryx"
   - `prompt`: See below

2. The subagent will:
   - Run the vetryx scan CLI command
   - Analyze any findings using AI reasoning (free - uses the current Claude session)
   - Determine which findings are real threats vs false positives
   - Return a concise summary

3. Report only the **summary** to the user in the main context

### Task Prompt Template

```
Run a Vetryx security scan and analyze the results.

**Step 1: Run the scan**
Execute this command:
\`\`\`bash
vetryx scan "${PATH:-$HOME/.claude/plugins}" ${FLAGS:---third-party-only} -f json
\`\`\`

**Step 2: Analyze findings**
For each finding, determine:
- Is this a real security threat or a false positive?
- What is the actual risk level?
- Should the user take action?

**Step 3: Return summary**
Provide a concise summary:
- Total files scanned
- Real threats found (with severity)
- False positives filtered out
- Recommended actions (if any)

Do NOT include raw scan output. Only return the analyzed summary.
```

Replace `${PATH}` with the user-provided path (default: `$HOME/.claude/plugins`)
Replace `${FLAGS}` with any flags the user specified
