# Architecture

```
/var/www/httpd-logs/<site>.audit.log ─┐  (ModSecurity v3, Serial)
                                      ├─ collector ─► store (events/YYYY-MM-DD.jsonl[.gz])
                                      │       └────► rules ─► Telegram / email / webhook
                                      │       └────► syslog (CEF / JSON) ─► SIEM
/etc/nginx/vhosts, vhosts-resources ──┴─ sites (names, owners, WAF mode)

web panel ─► policy ─► /etc/wafisp/modsec/{before,after}.conf, allow.txt, deny.txt ─► nginx -t ─► reload
          └► block  ─► ipset + iptables  |  policy deny list  |  mgrctl firewall
```

One process (`wafisp`) runs the collector, the alert pipeline, the SIEM forwarders, the expiry jobs and the web panel.

## Audit logs

nginx's ModSecurity connector writes one Serial audit log per site (`SecAuditLog` in `vhosts-resources/<site>/modsecurity.conf`). An entry is a run of sections between boundary lines `---<id>---<letter>--`. The parser keeps:

- A: time, unique id, source and destination address;
- B: request line and headers (Host, User-Agent and Referer are pulled out);
- C: the request body, cut to 4 KB;
- F: the response status;
- H: one `ModSecurity:` line per matched rule, with the rule id, message, data, severity, tags, the matched variable, and "Access denied" on the rule that blocked.

The anomaly score is the value 949110 compared with the threshold; without it (DetectionOnly below the threshold) the score is summed from CRS severities. The class of an event comes from the strongest attack rule's id range (942 SQL injection, 941 XSS, 930 path traversal, ...).

The collector follows every log like `tail -f` and remembers, per file, the inode and the offset after the last complete entry, so an entry still being written is read again on the next pass. ISPmanager rotates the logs with `copytruncate`: a file that shrank is read from the start. On the first start the current logs are read into the store without raising alerts.

## Store

Every event is a JSON line in `data_dir/events/<date>.jsonl`; closed days are gzipped and days past `retention` deleted. A compact summary of every event of the retention period stays in memory and serves the overview, the attack log, the analysis and the CSV export. The event card reads the full event back from its day file.

## Panel rules

The panel owns `rules_dir` (`/etc/wafisp/modsec`) and rewrites it from `data_dir/policy.json`:

| File | Loaded | Content |
|---|---|---|
| `before.conf` | before CRS | `allow.txt` → `ctl:ruleEngine=DetectionOnly` (logged, never blocked); `deny.txt` → `deny,status:403`; site modes (`ctl:ruleEngine=` by Host); traps (`REQUEST_FILENAME @beginsWith` path, by Host for one site: `deny,status:403,log,auditlog`, or `pass` in dry run); exclusions limited to a site or a path (`ctl:ruleRemoveById`, `ctl:ruleRemoveTargetById`, ...) |
| `after.conf` | after CRS | exclusions for every site (`SecRuleRemoveById`, `SecRuleUpdateTargetById`) |
| `allow.txt`, `deny.txt` | by `@ipMatchFromFile` | addresses and subnets |

Rule ids: 7710001–7710002 (lists), 77101xx (site modes), 7711000 + exclusion id (exclusions), 7720000 + trap id (traps). The auto-ban bans every address that falls into a trap, whether the auto-ban itself is on or not, at most once an hour per address and trap, and stores the rule that fired with the block. Every value that ends up in a directive is validated against a strict pattern first.

A change writes the files, runs `nginx -t`, and only then reloads nginx. When the test fails the previous files are put back and the change is refused. A reload is postponed while the host has less than `min_avail_mb` available (each reload starts workers that load the whole rule set again) and retried every minute.

## Blocking

`blocks.json` is the source of truth: who blocked which address, why, until when and through which backends. Every minute expired entries are removed and every backend is brought in line with the list, which also restores the ipset and the iptables rule after a reboot or after ISPmanager rewrote its chains.

- `ipset`: sets `<name>4` and `<name>6` (`hash:net`), one iptables/ip6tables rule inserted first in `INPUT`, `-p tcp -m multiport --dports <ports> -j DROP`, comment `wafisp-panel`.
- `modsec`: the deny list in `before.conf`. Sites in DetectionOnly only log these requests.
- `ispmgr`: `mgrctl -m ispmgr firewall.edit type=deny`; the panel only touches rules whose comment starts with `wafisp-panel`.

Addresses that can never be blocked: the requester's own, private, loopback and link-local ranges, the host's own addresses and the `protected` list.

## Analysis

Possible false positives are groups of (site, rule, variable, path) ranked by how many *focused* addresses hit them: addresses that touched at most three paths in the period. A scanner tries hundreds of URLs and drops out; a form the WAF breaks is hit by every visitor who uses it. Rules that fire almost only on scanners (numeric Host, scanner User-Agent, `.env`/`.git`) are marked.

## Web panel

Server-rendered HTML, embedded assets, no build step, charts as inline SVG. Sessions are HMAC-signed cookies bound to the user's password version; every form carries a CSRF token and POSTs check `Origin`. Viewers read everything; only admins block, allow, exclude and change modes, and each of those actions is written to the audit log with its reason.
