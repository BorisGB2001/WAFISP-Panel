# WAFISP Panel

A panel for the WAF of an [ISPmanager](https://www.ispmanager.com/) host: ModSecurity v3 with the OWASP Core Rule Set running in nginx ("WAF module for Nginx"). ISPmanager turns the WAF on per site and writes one audit log per site. It gives no overview, no search, no blocking and only a crude per-site rule list. WAFISP Panel is a single Go binary on the same host that reads those audit logs and adds:

- **Overview** of what the WAF blocked and let through: events over time, attack classes, top attackers, sites, rules, paths and countries, and the health of every audit log.
- **Attack log** with filters (period, site, address, path, rule, matched variable, class, action, anomaly score), CSV export, and an event card that shows the request, every matched rule with its variable and data, and "copy as cURL".
- **Analysis**: possible false positives (the same rule on the same site, path and variable hit by many ordinary visitors rather than scanners), top attackers, rules, paths and countries.
- **Blocking** of addresses and subnets for a set time, through any of:
  - `ipset`: the panel's own set, dropped by one iptables rule on the web ports; instant, no nginx reload;
  - `modsec`: a deny list in the panel's ModSecurity rules; requests get 403 and land in the site's audit log;
  - `ispmgr`: a deny rule in ISPmanager's firewall, visible in ISPmanager.
- **Auto-ban** of addresses that keep attacking: N denied requests within a window, or one denied request of a dangerous class. A repeat offender is blocked for longer each time (a day, a week, for good by default). A dry-run mode records whom it would block. One-click "for a day" / "for good" buttons sit next to every address in the attack log.
- **Allow list**: addresses the WAF does not inspect.
- **Exclusions** that switch CRS rules off where they break legitimate requests, scoped to a site, a path prefix and one request variable. Every change goes through `nginx -t` first and is rolled back if nginx refuses it.
- **Site modes**: switch a site to DetectionOnly or off without touching ISPmanager.
- **Alerts** to Telegram, email and webhooks by rules; **SIEM forwarding** over syslog as CEF or JSON.
- **Users and audit**: `admin` and `viewer` roles, bcrypt, login throttling, CSRF protection, and an audit log of every action.
- **English and Russian** UI.

The panel never edits ISPmanager's own files. Its rules live in a directory of their own (`/etc/wafisp/modsec`, outside `/etc/modsecurity`, which ISPmanager owns), which nginx loads around the CRS rules (see [Deployment](docs/DEPLOYMENT.md)). Every five minutes the panel checks that nginx still loads them and warns on every page and in `system_channels` when an update removed the include. It never edits nginx's config itself.

## Quick start

Requirements: Go 1.25+, an ISPmanager host with the nginx WAF module (ModSecurity v3, CRS 4) and audit logs in Serial format.

```bash
make test
make linux VERSION=0.1.0          # bin/wafisp-linux-amd64
cp deploy/wafisp.example.yaml wafisp.yaml
```

Edit `wafisp.yaml`, copy the project to the host and run `sh deploy/install.sh wafisp.yaml secrets` as root. The first password of `admin` is in `/var/lib/wafisp/initial-admin-password`.

## Command line

| Flag | Purpose |
|---|---|
| `-config path` | config file, `/etc/wafisp/wafisp.yaml` by default |
| `-check` | validate the config, parse every audit log, list the sites, and say whether nginx loads the panel's rules; changes nothing |
| `-parse file` | parse one audit log and print a summary |
| `-test-channel name` | send a test alert to one channel and exit |
| `-dry-run` | log alerts instead of sending them, send nothing to SIEM, run no expiry jobs |
| `-reset-password user` | set a random password and print it |
| `-version` | print the version |

## Documentation

- [Architecture](docs/ARCHITECTURE.md): how the panel reads, stores, blocks and applies rules
- [Deployment](docs/DEPLOYMENT.md): install, the nginx include, safety, data on disk
