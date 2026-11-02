#!/bin/sh
# boris.gb 2026-11-02 09:57 - installs WAFISP Panel on an ISPmanager host: binary, config, secrets, rules dir, systemd unit.
# Run from the project root: sh deploy/install.sh [wafisp.yaml secrets-dir]
# Without arguments it only updates the binary and the unit. From the secrets dir it takes *.token, *.password, *.secret.
# It never touches nginx's config: loading the panel's rules is a separate, manual step (docs/DEPLOYMENT.md).
set -eu

CFG=${1:-}
SECRETS=${2:-}
BIN=bin/wafisp-linux-amd64

[ -f "$BIN" ] || { echo "no $BIN, run make linux" >&2; exit 1; }

install -d -m 0750 /etc/wafisp /etc/wafisp/secrets
install -d -m 0700 /var/lib/wafisp
# boris.gb 2026-11-02 11:20 - the rules dir lives under /etc/wafisp: ISPmanager owns /etc/modsecurity
install -d -m 0755 /etc/wafisp/modsec
install -m 0755 "$BIN" /usr/local/bin/wafisp.new
install -m 0644 deploy/wafisp.service /etc/systemd/system/wafisp.service

if [ -n "$CFG" ]; then
    install -m 0640 "$CFG" /etc/wafisp/wafisp.yaml.new
fi
if [ -n "$SECRETS" ]; then
    for f in "$SECRETS"/*.token "$SECRETS"/*.password "$SECRETS"/*.secret; do
        [ -f "$f" ] && install -m 0600 "$f" /etc/wafisp/secrets/
    done
fi

# Check the new binary with the new config before switching over: -check
# only reads (config, audit logs, sites) and changes nothing.
NEWCFG=/etc/wafisp/wafisp.yaml
[ -f /etc/wafisp/wafisp.yaml.new ] && NEWCFG=/etc/wafisp/wafisp.yaml.new
/usr/local/bin/wafisp.new -config "$NEWCFG" -check

[ -f /etc/wafisp/wafisp.yaml ] && cp -p /etc/wafisp/wafisp.yaml "/etc/wafisp/wafisp.yaml.bak-$(date +%Y%m%d%H%M)"
[ -f /etc/wafisp/wafisp.yaml.new ] && mv /etc/wafisp/wafisp.yaml.new /etc/wafisp/wafisp.yaml
mv /usr/local/bin/wafisp.new /usr/local/bin/wafisp

systemctl daemon-reload
systemctl enable wafisp
systemctl restart wafisp
sleep 3
systemctl --no-pager status wafisp | head -5
curl -s 127.0.0.1:9189/healthz; echo
[ -f /var/lib/wafisp/initial-admin-password ] && echo "First sign-in password of admin: /var/lib/wafisp/initial-admin-password; change it in the panel"
exit 0
