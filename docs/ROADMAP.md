# Roadmap

Planned work, newest ideas last. Done items move to the release notes.

## Default traps

Ship a set of traps for paths nobody legitimate requests, so a fresh install catches common scanners from day one:

| Path | Match | Why |
|---|---|---|
| `.env` | contains | environment files with database passwords and API keys |
| `.git` | contains | the repository: source code, history, sometimes credentials |
| `.aws` | contains | AWS credentials (`.aws/credentials`, `.aws/config`) |
| `phpinfo.php` | contains | server configuration dump |
| `.zshrc` | contains | shell config in a home directory left in the web root |
| `.bashrc` | contains | the same, for bash |

How it should work:

- Every site, matched anywhere in the path ("contains"), like a trap made by hand.
- Created once, on the first start of a version that has them, or with an "Add the default traps" button on the Traps page. Never re-created after an admin deletes one.
- Start in dry run: the panel records whom each trap would ban, and the admin switches it to banning after a look at the hits. Proposed ban: 7 days.
- Each default trap is marked as such in the list, with its reason filled in ("default trap: scanners look for …").

Check before shipping:

- `.git` as "contains" also matches `/.github/…` and `/.gitignore`. That is fine for `.gitignore`, but `/.github/` can be a legitimate path on some sites. Either match `/.git/` and `/.git` at the end, or show the sites' recent requests to these paths before turning the trap on.
- `.env` as "contains" matches `/.env`, `/.env.bak`, `/app/.env`, but also any path with `.env` inside a longer name (`/files/report.envelope.pdf`). Check the hits on the three servers in dry run first.
- Addresses on the allow list and protected networks are never banned, as with every trap.
