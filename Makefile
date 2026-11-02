# boris.gb 2026-11-02 09:57 - WAFISP Panel: build and test; linux-amd64 for the Debian ISPmanager host
# boris.gb 2026-11-02 10:14 - 0.1.1: /healthz reports whether the logs are read, not whether attacks arrived
# boris.gb 2026-11-02 11:40 - 0.2.0: auto-ban with escalation and dry run, one-click ban, self-check of the nginx include, rules dir in /etc/wafisp/modsec
# boris.gb 2026-11-02 12:00 - 0.2.1: blocked addresses in red, "Blocked" page (new time, to the allow list, unblock), IP search
# boris.gb 2026-11-02 12:15 - 0.2.2: ban everyone who used an attack (preview, one sync for the batch)
# boris.gb 2026-11-02 19:12 - 0.2.3: web.allow_from (403 for other sources), block form layout, address page block line
# boris.gb 2026-11-02 20:33 - 0.2.4: allow list logs instead of ignoring and is never banned, who/when/why on blocked addresses, blocked IPs in red
# boris.gb 2026-11-02 21:15 - 0.2.5: attack log shows one status per address (🔒 blocked, ✓ allowed, ⛔ ban button only for the rest)
VERSION ?= 0.2.5
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: build linux test

build:
	go build -ldflags '-X main.version=$(VERSION)-dev' -o bin/wafisp ./cmd/wafisp

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='$(LDFLAGS)' -o bin/wafisp-linux-amd64 ./cmd/wafisp

test:
	go vet ./cmd/... ./internal/...
	go test ./cmd/... ./internal/...
