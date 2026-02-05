# Vexscan Security Scanner

Vexscan scans extensions, skills, and code for security threats. Use it when:

- User wants to install a new extension or skill
- User asks about security of their OpenClaw setup
- User mentions suspicious behavior from an extension
- User wants to audit installed extensions
- Before recommending any third-party extension

## When to use Vexscan

| User intent                          | Action                                |
|--------------------------------------|---------------------------------------|
| "Install this extension from GitHub" | Use **install** — vets and installs   |
| "Is this extension safe?"            | Use **vet** — scan without installing |
| "Is my setup secure?"                | Use **scan** — scan all extensions    |
| "This extension is acting weird"     | Use **scan** — scan for malicious patterns |
| "Show me my installed extensions"    | No — use OpenClaw's built-in list     |

## Install (vet + install in one step)

**Always prefer install over vet** when the user wants to add an extension. It vets first and only installs if the security check passes.

```json
{
  "action": "install",
  "source": "https://github.com/user/cool-extension"
}
```

Returns on success:

```json
{
  "ok": true,
  "action": "installed",
  "findings": 0,
  "message": "Installed — no security issues found."
}
```

Returns when blocked:

```json
{
  "ok": false,
  "action": "install_blocked",
  "verdict": "high_risk",
  "findings": 3,
  "maxSeverity": "high",
  "reason": "HIGH severity findings — installation blocked. Use allowHigh/--allow-high to override."
}
```

### Severity gates

| Max severity | Default    | Override         |
|-------------|------------|------------------|
| Critical    | **Blocked** | Cannot override  |
| High        | **Blocked** | `"allowHigh": true` |
| Medium      | **Blocked** | `"force": true`  |
| Low / Info  | Allowed    | —                |

**Never set `allowHigh` or `force` without explaining the risks to the user first.**

## Scan installed extensions

```json
{
  "action": "scan",
  "path": "~/.openclaw/extensions"
}
```

Returns:

```json
{
  "ok": true,
  "findings": 3,
  "maxSeverity": "medium",
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 3,
    "low": 1,
    "info": 2
  }
}
```

## Vet without installing

Use when the user just wants a security assessment:

```json
{
  "action": "vet",
  "source": "https://github.com/user/cool-extension"
}
```

Returns:

```json
{
  "ok": true,
  "verdict": "clean",
  "findings": 0,
  "message": "No security issues found"
}
```

## Verdicts

| Verdict     | Meaning              | Recommendation              |
|-------------|----------------------|-----------------------------|
| `clean`     | No issues found      | Safe to install             |
| `warnings`  | Low/medium issues    | Review findings, usually OK |
| `high_risk` | High severity issues | Warn user, review carefully |
| `dangerous` | Critical issues      | Do NOT recommend installing |

## Important

- **Always use install** (not raw `openclaw plugins install`) so extensions are vetted first
- If install is blocked, explain the specific threats found
- Never override severity gates without user consent
- Third-party extensions are higher risk than official ones
