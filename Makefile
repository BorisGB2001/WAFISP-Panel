# boris.gb 2026-11-02 09:57 - WAFISP Panel: build and test; linux-amd64 for the Debian ISPmanager host
# boris.gb 2026-11-02 10:14 - 0.1.1: /healthz reports whether the logs are read, not whether attacks arrived
# boris.gb 2026-11-02 11:40 - 0.2.0: auto-ban with escalation and dry run, one-click ban, self-check of the nginx include, rules dir in /etc/wafisp/modsec
# boris.gb 2026-11-02 12:00 - 0.2.1: blocked addresses in red, "Blocked" page (new time, to the allow list, unblock), IP search
# boris.gb 2026-11-02 12:15 - 0.2.2: ban everyone who used an attack (preview, one sync for the batch)
# boris.gb 2026-11-02 19:12 - 0.2.3: web.allow_from (403 for other sources), block form layout, address page block line
# boris.gb 2026-11-02 20:33 - 0.2.4: allow list logs instead of ignoring and is never banned, who/when/why on blocked addresses, blocked IPs in red
# boris.gb 2026-11-02 21:15 - 0.2.5: attack log shows one status per address (🔒 blocked, ✓ allowed, ⛔ ban button only for the rest)
# boris.gb 2026-11-02 21:26 - 0.3.0: path traps (ban whoever requests a path), path menu in the top paths, the rule behind every automatic ban
# boris.gb 2026-11-02 21:40 - 0.3.1: allowed addresses green in top attackers, trapped paths red, path menu on the address page events
# boris.gb 2026-11-02 21:47 - 0.3.2: traps on a part of the path (contains), remembered "hide blocked" / "hide trapped" switches
# boris.gb 2026-11-02 23:39 - 0.3.3: attack log pager fixed (filter queries were escaped), hide blocked/passed in the log, strict network format, /16 on the allow list, hide paths only allowed addresses used
# boris.gb 2026-11-03 00:07 - 0.3.4: Show button aligned with the period, "today" period from midnight, deleting a trap offers to unblock the addresses it banned
# boris.gb 2026-11-03 00:29 - 0.3.5: the period chosen in the selector is remembered until changed; "make release" tags and publishes a GitHub release
# boris.gb 2026-11-03 00:41 - 0.4.0: updates from GitHub (signed releases, one click, automatic rollback), release signing key
# boris.gb 2026-11-03 01:16 - 0.5.0: Visitors page from the access logs, client type in the attack log, default traps
# boris.gb 2026-11-03 01:36 - 0.5.1: Cloudflare addresses never blocked (old blocks lifted), sites without WAF highlighted, update page waits and reloads, notes in the panel's language
VERSION ?= 0.5.1
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: build linux test release

build:
	go build -ldflags '-X main.version=$(VERSION)-dev' -o bin/wafisp ./cmd/wafisp

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='$(LDFLAGS)' -o bin/wafisp-linux-amd64 ./cmd/wafisp

test:
	go vet ./cmd/... ./internal/...
	go test ./cmd/... ./internal/...

# boris.gb 2026-11-03 00:29 - release: tag v$(VERSION) on the current commit and publish a GitHub release with the
# Linux binary and its checksum, so the version shows on GitHub. Needs a clean tree, the commit pushed, and gh.
# boris.gb 2026-11-03 00:40 - the release is signed: the panel's updater installs only binaries this key signed.
RELEASE_KEY ?= $(HOME)/.config/wafisp-release/release.key
# boris.gb 2026-11-03 01:34 - Russian release notes from docs/releases/v$(VERSION).ru.md, shown by the panel in Russian.

release: test linux
	@test -z "$$(git status --porcelain)" || { echo "commit first" >&2; exit 1; }
	cd bin && shasum -a 256 wafisp-linux-amd64 > wafisp-linux-amd64.sha256
	go run ./cmd/wafisp -sign $(RELEASE_KEY) bin/wafisp-linux-amd64
	git tag -a v$(VERSION) -m "$$(git log -1 --format=%s)"
	git push origin v$(VERSION)
	gh release create v$(VERSION) bin/wafisp-linux-amd64 bin/wafisp-linux-amd64.sha256 bin/wafisp-linux-amd64.sig --title "v$(VERSION)" --notes "$$(git log -1 --format=%B | sed '/^Co-Authored-By/d'; if [ -f docs/releases/v$(VERSION).ru.md ]; then printf '\n\n<!-- ru -->\n'; cat docs/releases/v$(VERSION).ru.md; fi)"
