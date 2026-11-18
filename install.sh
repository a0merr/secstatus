#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
sudo install -m 755 secstatus.py /usr/local/bin/secstatus
sudo install -m 644 secstatus.service /etc/systemd/system/secstatus.service
install -Dm 755 secstatus-notify ~/.local/bin/secstatus-notify
install -Dm 644 secstatus-notify.service ~/.config/systemd/user/secstatus-notify.service
install -Dm 644 security.conf ~/.config/conky/security.conf
sudo systemctl daemon-reload && sudo systemctl restart secstatus
systemctl --user daemon-reload && systemctl --user restart secstatus-notify
