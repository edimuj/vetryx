# /vetryx:vet

Vet a plugin before installation - scan from GitHub URL or local path.

## Usage

```
/vetryx:vet <source>
```

## Examples

- `/vetryx:vet https://github.com/user/claude-plugin` - Vet from GitHub
- `/vetryx:vet ./downloaded-plugin` - Vet local directory

## What It Does

1. Clones the repository (if GitHub URL) to a temp directory
2. Runs a full security scan
3. Reports verdict: CLEAN, WARNINGS, HIGH RISK, or DANGEROUS
4. Cleans up temp files

## Verdicts

- **CLEAN** - No issues found, safe to install
- **WARNINGS** - Minor issues, review before installing
- **HIGH RISK** - Serious issues found, install with caution
- **DANGEROUS** - Critical issues, do not install

## Instructions

When the user wants to vet a plugin before installing:

1. Run `vetryx vet <source>` on the provided URL or path
2. Show the full scan output including findings
3. Provide a clear recommendation based on the verdict
4. If DANGEROUS, strongly advise against installation
5. If issues found, explain what each finding means

Run the vet with:
```bash
vetryx vet "$1" --skip-deps
```
