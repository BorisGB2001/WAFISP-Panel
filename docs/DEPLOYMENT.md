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

## Visitors and access logs

The Visitors page reads the sites' nginx access logs (`access_logs.glob`, by default `*.access.log` next to the audit logs; ISPmanager writes them to `/var/www/httpd-logs/`). It needs nginx's standard "combined" format, which ISPmanager uses. The panel follows each log like the audit logs: it remembers how far it read, and after a rotation it starts over on the new file. It keeps only hourly counts per site, in `data_dir/visitors/YYYY-MM-DD.json.gz`, for `access_logs.retention` (a year). So the logs can be rotated and deleted by ISPmanager without losing the statistics; lines appended in the seconds between the panel's last read and a rotation may be missed. Set `access_logs.disabled: true` to turn it off.

ISPmanager writes a site's access log only when the site's request log is on (Sites → the site → Logs → Request log); otherwise its vhost has `access_log off` and the site is not counted. The Visitors page shows which sites have it off, and an admin can turn it on or off there, for one site or for all of them at once. The panel does this the way ISPmanager's own form does, through `mgrctl -m ispmgr webdomain.edit elid=<site> log_access=on|off`; ISPmanager then rewrites the vhost and reloads nginx itself, and rotates the new logs. Each switch goes to the audit log. Set `access_logs.read_only: true` to hide the buttons.

The same lines feed the auto-ban's access-log rules (Auto-ban page, "From the access logs"): N pages answered 404 from one address within the window (images, styles, scripts and other assets do not count), N POSTs to the login pages, or N requests a minute. Known search engine bots are skipped. The rules are off and in dry run until an admin turns them on, apart from the WAF rules, and share their durations, escalation and backends. Lines older than the window, such as a log read from its start after the first install, count towards nothing. The log is read every 10 seconds, so a ban lands within about that.

## Default traps

On hosts where nginx does not load the panel's rules (step 1, `nginx.reload: []`), the panel adds the default traps once, in dry run with a 7-day ban: `/.env`, `/.git/`, `/.aws/`, `/phpinfo.php`, `/.zshrc`, `/.bashrc`, each matched anywhere in the path. Where adding them would reload nginx, the Traps page offers them with a button instead. A default trap that is deleted is not added again.

## Shared blocks

Panels on several servers can share their blocks through a private GitHub repository. Each panel writes `blocks/<name>.json`: the list of the blocks it made itself (by hand, auto-ban, traps, mass bans), with their terms and reasons, signed with its own ed25519 key. Every `interval` (a minute) it pulls the lists of its peers, checks their signatures against the keys in its config, and puts its blocks in line: new addresses are blocked, extended terms follow, addresses lifted or expired there are unblocked here. Blocks that came from a peer are not published again, so nothing loops. An older copy of a list than the one already applied is refused.

Each server keeps the last word. A peer's address is skipped when it is protected here (private ranges, the host, `block.protected`, Cloudflare), on this server's allow list, or already blocked here by this server. A peer's block unblocked here by hand stays unblocked until that server bans the address anew. A term changed here by hand stands until that server changes its own. Taking a peer out of `peers` lifts its blocks at the next start.

To set it up:

1. Create a private repository with a README, e.g. `wafisp-share`.
2. On every server make two keys; neither leaves the server:
   - `wafisp -genkey /etc/wafisp/secrets/share.key` signs the server's list and prints its public key, for the other servers' `peers`;
   - `ssh-keygen -t ed25519 -N '' -C wafisp-<name> -f /etc/wafisp/secrets/share-deploy.key` is the server's deploy key. Add `share-deploy.key.pub` to the repository's Settings → Deploy keys with "Allow write access". It can write to that repository and nothing else.

   The panel speaks git over SSH to github.com:22 itself (git is not needed on the host) and checks GitHub's pinned host key. Instead of a deploy key, `token_file` can hold a fine-grained token with "Contents: read and write" on that repository only; the panel then uses the GitHub API over HTTPS.
3. Add the `share` section to every server's config with its own `name` and the other servers' public keys under `peers` (see `deploy/wafisp.example.yaml`), and restart the panel.
4. The "Shared blocks" page shows every server: when its list was made, how many blocks it has, how many were applied here, which were skipped and why. With `apply: false` (the default) the peers' blocks are only counted as "would block". Check them, then set `apply: true` and restart.

Peers' blocks go through `share.backends`, `[ipset]` by default. On the Blocked page they show "from server <name>", and the filter "other servers" lists them.

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
- A site's request log is switched only through ISPmanager (`mgrctl webdomain.edit`), by an admin's click; the panel never edits the vhost. `access_logs.read_only: true` turns this off.
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
