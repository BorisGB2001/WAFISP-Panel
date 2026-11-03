# AGENTS.md

Instructions for AI coding agents (Codex, Claude Code, Cursor, Copilot and others) that deploy or change WAFISP Panel. Humans: see [README](README.md) and [Deployment](docs/DEPLOYMENT.md).

WAFISP Panel runs as root on a production ISPmanager host, next to the customers' sites. A mistake here takes sites down or locks people out. When a rule below and a request seem to conflict, stop and ask the human.

## Never

- **Never edit files that ISPmanager owns.** It rewrites them on updates and whenever a site changes, so your edit is lost or breaks the next rewrite. This means:
  - `/etc/nginx/vhosts/` and `/etc/nginx/vhosts-resources/` (the sites' nginx config);
  - `/etc/modsecurity/` (CRS and the WAF module's config);
  - ISPmanager's templates and anything under `/usr/local/mgr5/` except through `mgrctl`.
- **Never change ISPmanager's firewall with iptables directly.** Use `mgrctl` or the panel's `ispmgr` backend. The panel's own ipset rule (comment `wafisp-panel`) is the only iptables rule it adds.
- **Never add the nginx include (step 2) on your own.** It is a human decision, made after step 1 has run for a while. If the human asks for it, follow [Step 2](docs/DEPLOYMENT.md#step-2-let-nginx-load-the-panels-rules) exactly, and run `nginx -t` before `systemctl reload nginx`. Never `restart` nginx.
- **Never repair nginx's config because the panel warns that its rules are not loaded.** Report the warning to the human.
- **Never expose the panel to the internet.** `web.listen` takes internal addresses only (office, VPN), or a public address with `web.allow_from` narrowed to known sources.
- **Never print, log, commit or paste secrets:** the admin's first password (`/var/lib/wafisp/initial-admin-password`), `/etc/wafisp/secrets/*` (the shared-blocks key and GitHub token included), `session.key`, tokens, the release signing key. Public keys printed by `wafisp -genkey` are fine to share. Tell the human where the file is.
- **Never commit production data.** The repository is public: no real IP addresses, domains, host names, user names or configs. Keep production configs in `ops/` (gitignored). Examples use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and `example.*` domains.
- **Never turn on auto-ban for real or switch traps out of dry run** without the human asking. Both start in dry run on purpose.

## Ask first

Production changes are outward-facing and hard to undo. Ask the human and wait for an explicit yes before each of these, every time:

- installing, upgrading or restarting the panel on a host;
- changing `/etc/wafisp/wafisp.yaml` on a host;
- reloading nginx;
- blocking or unblocking addresses, or editing the allow list, on a real host;
- turning on `share.apply` or adding a server to `share.peers`: its blocks then apply on this host too;
- `git push`, `make release`, or publishing a GitHub release.

Approval of one step does not cover the next.

## Deploying to a host

Gather first, from the human: the host, the internal address the panel will listen on, the addresses allowed to open it, and the addresses that must never be blocked (the human's own address, office, VPN, monitoring).

1. **Look before you touch.** Read-only commands only:
   ```bash
   nginx -V 2>&1 | grep -o modsecurity   # the WAF module is there
   ls /var/www/httpd-logs/*.audit.log      # one Serial audit log per site
   systemctl is-active nginx
   ```
   If something does not match the requirements in the [README](README.md#quick-start), stop and report.
2. **Build or download.** `make test && make linux`, or take `wafisp-linux-amd64` from the latest [release](https://github.com/BorisGB2001/WAFISP-Panel/releases) and check its `.sha256`.
3. **Write the config** from [deploy/wafisp.example.yaml](deploy/wafisp.example.yaml). Required:
   - `web.listen`: internal addresses only;
   - `web.allow_from`: the sources allowed to open the panel; include `127.0.0.1` if the human uses an SSH tunnel;
   - `block.protected`: private ranges plus the human's own addresses and the host's public address.

   For step 1 (read-only, the default for a new host) also set:
   ```yaml
   nginx:
     include_file: none
     reload: []
   block:
     backends: [ipset, ispmgr]   # no modsec until step 2
   ```
4. **Install.** Copy the project to the host and run as root: `sh deploy/install.sh wafisp.yaml secrets`. The installer runs `-check` before switching over and never touches nginx.
5. **Verify**, and report each result:
   ```bash
   systemctl is-active wafisp
   curl -s 127.0.0.1:9189/healthz            # 200
   wafisp -config /etc/wafisp/wafisp.yaml -check
   curl -sk -o /dev/null -w '%{http_code}\n' https://<a site>/            # still 200
   curl -sk -o /dev/null -w '%{http_code}\n' 'https://<a site>/?id=1%27%20OR%201=1--'   # 403 where the WAF blocks
   ```
   nginx's master PID must be the same before and after: the install does not reload nginx.
6. **Hand over.** Tell the human the panel's URL and that the first password is in `/var/lib/wafisp/initial-admin-password`; it disappears once they change the password in the panel. Do not read it out.

Later upgrades: the Update page in the panel, by an admin's click. It installs only signed releases and rolls back by itself. `sh deploy/install.sh` without arguments also works.

Undo: [Undo everything](docs/DEPLOYMENT.md#undo-everything).

## Changing the code

- Go, standard library first; the only notable dependencies are in `go.mod`. Run `make test` (vet + tests) before saying a change works.
- Layout: `cmd/wafisp` (main, flags, installer), `internal/*` (one package per concern: `modsec` parses audit logs, `collector` follows them, `store` keeps events, `block` blocks, `policy` writes the panel's ModSecurity rules, `update` self-updates, `visitors` reads access logs, `web` is the UI). See [Architecture](docs/ARCHITECTURE.md).
- UI: `internal/web/templates/*.html` (html/template) and `internal/web/static/`. The CSP allows only `script-src 'self'`: put JavaScript in static files, not inline.
- Every user-visible string is English in the code and gets its Russian translation in `internal/i18n/ru_wafisp.go` in the same change. Keep the map gofmt-aligned.
- Config files that allow comments (YAML, shell, systemd, nginx, Makefile) carry a comment next to each change: `<author> YYYY-MM-DD HH:MM - what and why`, time from `date '+%Y-%m-%d %H:%M'`.
- Anything that writes outside the panel's own directories must be opt-in and documented in [Safety](docs/DEPLOYMENT.md#safety).
- New config keys get a default in `internal/config`, a commented example in `deploy/wafisp.example.yaml`, and a line in the docs.
- README screenshots use made-up demo data only.

## Releases

Maintainer only. `make release VERSION=x.y.z` from a clean, pushed tree: it tests, builds, signs with `~/.config/wafisp-release/release.key`, tags and publishes. Russian notes go in `docs/releases/vX.Y.Z.ru.md`. Never read, print, copy or move the signing key; without it, stop and ask the maintainer.
