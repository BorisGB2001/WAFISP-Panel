# Deployment

## Where it runs

On the ISPmanager host itself, as root (it reads every site's audit log, manages ipset and iptables, tests and reloads nginx and calls `mgrctl`). Listen only on internal addresses (office network, VPN); the panel port should not be open to the internet. `web.allow_from` narrows it further: any other source gets 403, the login page included.

## Install and upgrade

```bash
make test && make linux VERSION=x.y.z
sh deploy/install.sh wafisp.yaml secrets   # first install, as root on the host
sh deploy/install.sh                        # upgrade: binary and unit only
```

`make release` tags the current commit `v<VERSION>` and publishes a GitHub release with the Linux binary and its checksum (needs `gh` and a clean, pushed tree).

The installer checks the new binary with the new config (`-check`, read-only) before switching over and keeps the previous config as `wafisp.yaml.bak-<date>`. It never changes nginx's configuration.

## Updates from the panel

Every 6 hours the panel asks GitHub for the latest release (`update.repo`, the project's own by default). When there is a newer one, admins see a banner and the "Update" page with the release notes. "Update" does this:

1. Download `wafisp-linux-amd64` and `wafisp-linux-amd64.sig` and check the ed25519 signature against the key built into the panel. A release signed with any other key is refused.
2. Run the new binary with `-version` (it must say the release's version) and `-config … -check` (it must accept the current config).
3. Start a one-shot unit with `systemd-run`, outside the panel's sandbox, which cannot write `/usr/local/bin`. That unit runs the old binary with `-apply-update`: it keeps the old binary as `/usr/local/bin/wafisp.prev`, puts the new one in place, restarts `wafisp`, and waits up to 90 seconds for systemd to report it active and for `/healthz` to answer 200. Otherwise it puts the old binary back.

The result shows on the "Update" page and in the audit log. "Roll back" swaps `wafisp` and `wafisp.prev`. The check needs outbound HTTPS to github.com. Without it, or to turn the check off, set `update.disabled: true`. `/healthz` needs `http.listen`; without it the installer relies on systemd alone.

Releases are signed by `make release` with the private key in `~/.config/wafisp-release/release.key`, which never leaves the maintainer's machine. To change keys, run `wafisp -genkey <file>`, put the printed public key in `internal/update/key.go`, and ship that version by hand once.

## Step 1: read-only

Right after the install the panel only reads: the overview, the attack log, the analysis and the alerts work, and the `ipset` backend can block (it does not depend on nginx). Rules written to `rules_dir` have no effect yet, and `-check` says so. To stay at this step on purpose, set `nginx.include_file: none` and `nginx.reload: []`, and leave `modsec` out of `block.backends`: the panel then neither reloads nginx nor warns that its rules are not loaded.

## Step 2: let nginx load the panel's rules

ISPmanager's WAF module loads CRS once, at the http level (`/etc/nginx/conf.d/modsecurity-crs.conf` on a host where it was moved there from the site files). Add the panel's files around it:

```nginx
modsecurity_rules_file /etc/wafisp/modsec/before.conf;   # allow/deny lists, site modes, scoped exclusions
modsecurity_rules_file /etc/modsecurity/admin/main.conf;      # CRS, as before
modsecurity_rules_file /etc/wafisp/modsec/after.conf;    # exclusions for every site
```

Then `nginx -t` and `systemctl reload nginx`. The panel writes all four files on start, so they exist before nginx includes them. Do not load them from the sites' files: a second copy of a rule makes `nginx -t` fail with "Rule id ... is duplicated".

After that, the `modsec` blocking backend, the allow list, site modes and exclusions apply.

## Safety

- Every rule change is tested with `nginx -t` before a reload, and rolled back when the test fails.
- Reloads wait while the host has less than `nginx.min_avail_mb` MB available.
- Values in rules (ids, tags, variables, paths, host names) are validated against strict patterns.
- The ipset rule drops only `block.ports` (80,443 by default), so a mistaken block never cuts SSH or the ISPmanager panel.
- Never blocked: the requester's address, private ranges, the host's own addresses and `block.protected`.
- An exclusion for every site and switching a site's WAF off need an explicit confirmation; every action needs a reason and goes to the audit log.

## Undo everything

```bash
systemctl disable --now wafisp
# remove the three modsecurity_rules_file lines for wafisp, then: nginx -t && systemctl reload nginx
iptables -D INPUT -m set --match-set wafisp4 src -p tcp -m multiport --dports 80,443 -m comment --comment wafisp-panel -j DROP
ip6tables -D INPUT -m set --match-set wafisp6 src -p tcp -m multiport --dports 80,443 -m comment --comment wafisp-panel -j DROP
ipset destroy wafisp4; ipset destroy wafisp6
# ISPmanager firewall: delete the rules with the comment "wafisp-panel"
```

## Data on disk

| Path | Content |
|---|---|
| `/etc/wafisp/wafisp.yaml` | config |
| `/etc/wafisp/secrets/` | channel secrets |
| `/etc/wafisp/modsec/` | the panel's ModSecurity rules (rewritten by the panel) |
| `/var/lib/wafisp/events/` | events, one file per day |
| `/var/lib/wafisp/cursors.json` | how far each audit log was read |
| `/var/lib/wafisp/policy.json` | allow list, deny list, exclusions, site modes |
| `/var/lib/wafisp/blocks.json` | blocks with their reasons and expiry |
| `/var/lib/wafisp/rules.yaml` | alert rules saved in the panel |
| `/var/lib/wafisp/users.json` | users (bcrypt) |
| `/var/lib/wafisp/session.key` | session signing key; deleting it ends every session |
| `/var/lib/wafisp/audit.log` | audit log of the panel |
| `/var/lib/wafisp/tls/` | self-signed certificate when none is configured |

`/healthz` and `/metrics` (Prometheus) are served on `http.listen`.
