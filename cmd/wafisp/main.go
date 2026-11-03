// Command wafisp is WAFISP Panel: it reads the ModSecurity audit logs of an
// ISPmanager host, sends alerts, forwards events to SIEM, blocks addresses
// and manages rule exclusions, and serves the web UI.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"wafisp/internal/auth"
	"wafisp/internal/autoban"
	"wafisp/internal/block"
	"wafisp/internal/collector"
	"wafisp/internal/config"
	"wafisp/internal/event"
	"wafisp/internal/geo"
	"wafisp/internal/history"
	"wafisp/internal/modsec"
	"wafisp/internal/notify"
	"wafisp/internal/pipeline"
	"wafisp/internal/policy"
	"wafisp/internal/rules"
	"wafisp/internal/share"
	"wafisp/internal/siem"
	"wafisp/internal/sites"
	"wafisp/internal/stats"
	"wafisp/internal/store"
	"wafisp/internal/update"
	"wafisp/internal/visitors"
	"wafisp/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/wafisp/wafisp.yaml", "path to the configuration file")
	check := flag.Bool("check", false, "validate the config, parse every audit log, show what would be applied and exit; changes nothing")
	parse := flag.String("parse", "", "parse one audit log file, print a summary and exit")
	testChannel := flag.String("test-channel", "", "send a test alert to the named channel and exit")
	dryRun := flag.Bool("dry-run", false, "log alerts instead of sending them; nothing goes to SIEM")
	resetPassword := flag.String("reset-password", "", "set a random password for the named panel user, print it and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	genKey := flag.String("genkey", "", "write a new signing key to this file (releases, shared blocks), print its public key and exit")
	signWith := flag.String("sign", "", "sign the files given as arguments with this key file (each gets a .sig) and exit")
	applyUpdate := flag.String("apply-update", "", "internal: install this staged release, restart the service, roll back if it fails")
	rollback := flag.Bool("rollback", false, "internal: put the previous binary back and restart the service")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *genKey != "" || *signWith != "" {
		if err := runSigning(*genKey, *signWith, flag.Args()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *applyUpdate != "" || *rollback {
		if err := runInstaller(*cfgPath, *applyUpdate); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *parse != "" {
		if err := runParse(*parse); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if *resetPassword != "" {
		if err := runResetPassword(*cfgPath, *resetPassword); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(*cfgPath, *check, *testChannel, *dryRun, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, check bool, testChannel string, dryRun bool, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	notify.Lang = cfg.Language
	if check {
		return runCheck(cfg)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hc := &http.Client{Timeout: 30 * time.Second}
	st := stats.New()
	if testChannel != "" {
		return runTestChannel(ctx, cfg, testChannel, hc)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}

	var g *geo.Geo
	if cfg.GeoIPDB != "" {
		if g, err = geo.OpenGeo(cfg.GeoIPDB); err != nil {
			log.Warn("no geo database, countries stay unknown", "err", err)
		}
	}
	events, err := store.Open(cfg.DataDir, cfg.Retention.D(), log)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer events.Close()

	hist, err := history.Open(filepath.Join(cfg.DataDir, "alerts-history.jsonl"), 1000)
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}
	ruleFile := filepath.Join(cfg.DataDir, "rules.yaml")
	activeRules, err := loadRules(cfg, ruleFile)
	if err != nil {
		return err
	}

	senders := map[string]notify.Sender{}
	channels := map[string]pipeline.AlertSink{}
	for _, ch := range cfg.Channels {
		s, err := notify.NewSender(ch, hc)
		if err != nil {
			return err
		}
		senders[ch.Name] = s
		q := &notify.Queue{Name: ch.Name, Sender: s, Log: log, Stats: st, Retries: 4, Backoff: 5 * time.Second, OnResult: hist.Delivered}
		q.Start(ctx, 1000)
		channels[ch.Name] = q
	}
	var targets []*siem.Syslog
	for _, sc := range cfg.SIEM {
		s, err := siem.NewSyslog(sc, log, st)
		if err != nil {
			return err
		}
		s.Start(ctx)
		targets = append(targets, s)
	}

	live := make(chan event.Event, 1000)
	p := &pipeline.Pipeline{Engine: rules.New(activeRules), Channels: channels, SIEM: targets, History: hist, Log: log, DryRun: dryRun}
	go p.Run(ctx, live)

	pol := newPolicy(cfg, log)
	if err := pol.Load(); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	blocks, err := newBlocks(cfg, pol, log)
	if err != nil {
		return err
	}
	siteReader := &sites.Reader{VhostsDir: cfg.Nginx.VhostsDir, ResourcesDir: cfg.Nginx.ResourcesDir}
	ban, err := autoban.Open(filepath.Join(cfg.DataDir, "autoban.json"))
	if err != nil {
		return fmt.Errorf("autoban: %w", err)
	}
	ban.Traps = func() []policy.Trap { st := pol.State(); return st.Traps }
	banEvents := make(chan event.Event, 1000)
	banRequests := make(chan accessLine, 5000)
	notice := func(severity, text string) {
		a := rules.Alert{ID: fmt.Sprint(time.Now().UnixNano()), Rule: "system", Severity: severity, Note: text,
			Channels: cfg.SystemChannels, First: time.Now(), Last: time.Now()}
		hist.Add(a)
		for _, n := range cfg.SystemChannels {
			if ch, ok := channels[n]; ok && !dryRun {
				ch.Enqueue(a)
			}
		}
	}

	col := &collector.Collector{
		Glob: cfg.ModSec.AuditGlob, Suffix: cfg.ModSec.AuditSuffix, State: filepath.Join(cfg.DataDir, "cursors.json"),
		Interval: cfg.ModSec.PollInterval.D(), Log: log, Flush: events.Flush,
		// Healthy means the logs were read lately, not that attacks came.
		OnPoll: func() {
			st.Instance("audit", func(s *stats.Instance) { s.LastPoll, s.LastOK = time.Now(), time.Now() })
		},
		Sink: func(ev *event.Event, isLive bool) {
			p := g.Lookup(ev.SrcIP)
			if p.Country != geo.Unknown {
				ev.Country, ev.City = p.Country, p.City
			}
			added, err := events.Add(ev)
			if err != nil {
				log.Error("store", "err", err)
				st.Add("store_errors_total", 1)
			}
			st.Instance("audit", func(s *stats.Instance) { s.Events++ })
			if added && isLive {
				select {
				case live <- *ev:
				case <-ctx.Done():
				}
				select {
				case banEvents <- *ev:
				default: // the auto-ban never holds up the collector
				}
			}
		},
	}
	st.Instance("audit", func(s *stats.Instance) { s.LastOK = time.Now() })
	go col.Run(ctx)

	health := &web.Health{}
	var upd *update.Updater
	if !cfg.Update.Disabled {
		exe, _ := os.Executable()
		upd = &update.Updater{Repo: cfg.Update.Repo, Current: version, Dir: filepath.Join(cfg.DataDir, "update"), ConfigPath: cfgPath,
			Exe: exe, PublicKey: releaseKey(), HTTP: &http.Client{Timeout: 5 * time.Minute}, Log: log}
		go upd.Loop(ctx, cfg.Update.Interval.D())
	}
	var visits *visitors.Store
	var visitLogs *visitors.Reader
	if !cfg.AccessLogs.Disabled {
		if visits, err = visitors.OpenStore(filepath.Join(cfg.DataDir, "visitors"), cfg.AccessLogs.Retention.D()); err != nil {
			return fmt.Errorf("visitors: %w", err)
		}
		visitLogs = &visitors.Reader{Glob: cfg.AccessLogs.Glob, Suffix: cfg.AccessLogs.Suffix, Store: visits,
			StateFile: filepath.Join(cfg.DataDir, "visitors", "cursors.json"), Every: 10 * time.Second, Log: log,
			// The auto-ban's access-log rules; a full queue drops lines rather than stall the reader.
			OnRequest: func(site string, r visitors.Request) {
				select {
				case banRequests <- accessLine{site, r}:
				default:
				}
			}}
		go visitLogs.Run(ctx)
	}
	syncer, err := newSyncer(cfg, blocks, pol, log)
	if err != nil {
		return err
	}
	ws := &web.Server{Cfg: cfg, Share: syncer, Store: events, Collector: col, Sites: siteReader, Policy: pol, Blocks: blocks,
		Autoban: ban, Health: health, Updater: upd, Visitors: visits, VisitorLogs: visitLogs,
		Senders: senders, Stats: st, History: hist, Rules: p, Log: log, Version: version, RuleFile: ruleFile}
	if err := ws.Open(activeRules); err != nil {
		return fmt.Errorf("web: %w", err)
	}

	// The panel's ModSecurity rules are written on start so a fresh rules
	// dir is never missing files nginx includes.
	actx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	if err := pol.Apply(actx); err != nil {
		log.Error("policy: apply on start", "err", err)
	}
	// The default traps arrive by themselves only where that needs no nginx
	// reload; elsewhere the Traps page offers them, since adding them
	// reloads nginx like any trap.
	if !pol.State().DefaultTraps && len(cfg.Nginx.Reload) == 0 {
		n := 0
		err := pol.Update(actx, func(s *policy.State) error { n = s.AddDefaultTraps(time.Now()); return nil })
		if err != nil {
			log.Error("policy: default traps", "err", err)
		} else {
			ws.Audit().Log("system", "", "trap.defaults", fmt.Sprintf("%d default traps added in dry run", n))
		}
	}
	cancel()

	// Blocks made before an address became protected (Cloudflare's, since
	// 0.5.1) are lifted: they cut off real visitors.
	if lifted, err := blocks.LiftProtected(actx); len(lifted) > 0 || err != nil {
		for _, e := range lifted {
			ws.Audit().Log("system", "", "unblock", e.IP+": protected address (e.g. Cloudflare), blocked by "+e.By)
		}
		if err != nil {
			log.Error("block: lift protected", "err", err)
		}
	}
	if !dryRun {
		go blocks.Run(ctx, func(ip string, err error) {
			detail := ip
			if err != nil {
				detail += ": " + err.Error()
				log.Error("block expiry failed", "ip", ip, "err", err)
			}
			ws.Audit().Log("system", "", "unblock.expired", detail)
		})
		go maintain(ctx, events, pol, ws, log)
		go runAutoban(ctx, ban, blocks, pol, banEvents, banRequests, ws, notice, log)
		if syncer != nil {
			syncer.Audit = func(action, detail string) { ws.Audit().Log("system", "", action, detail) }
			go syncer.Run(ctx, cfg.Share.Interval.D())
		}
		if cfg.Nginx.IncludeFile != "none" {
			go checkHealth(ctx, cfg, pol, health, notice, log)
		}
	}

	if cfg.HTTP.Listen != "" {
		go serveHTTP(ctx, cfg.HTTP.Listen, st, 5*time.Minute, log)
	}
	webErr := make(chan error, 1)
	if len(cfg.Web.Listen) > 0 {
		go func() { webErr <- ws.ListenAndServe(ctx) }()
	}

	log.Info("started", "version", version, "events", events.Len(), "rules", len(activeRules), "channels", len(cfg.Channels),
		"siem", len(cfg.SIEM), "web", cfg.Web.Listen, "backends", blocks.Names(), "dry_run", dryRun)
	select {
	case <-ctx.Done():
	case err := <-webErr:
		if err != nil {
			return fmt.Errorf("web: %w", err)
		}
	}
	log.Info("stopping")
	return nil
}

// maintain runs the periodic jobs: allowed addresses expire, postponed
// reloads are retried, and old events leave the store.
func maintain(ctx context.Context, events *store.Store, pol *policy.Manager, ws *web.Server, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	lastStore := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		var gone []string
		for _, a := range pol.State().Allow {
			if !a.Expires.IsZero() && now.After(a.Expires) {
				gone = append(gone, a.IP)
			}
		}
		if len(gone) > 0 {
			cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			err := pol.Update(cctx, func(s *policy.State) error { s.ExpireAllow(now); return nil })
			cancel()
			detail := strings.Join(gone, ", ")
			if err != nil {
				detail += ": " + err.Error()
				log.Error("allow expiry failed", "err", err)
			}
			ws.Audit().Log("system", "", "allow.expired", detail)
		}
		cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		pol.RetryPending(cctx)
		cancel()
		if now.Sub(lastStore) > time.Hour {
			lastStore = now
			events.Maintain(now)
		}
	}
}

// newSyncer prepares the exchange of blocks with other servers; nil when
// it is not configured.
func newSyncer(cfg *config.Config, blocks *block.Manager, pol *policy.Manager, log *slog.Logger) (*share.Syncer, error) {
	sh := cfg.Share
	if sh == nil {
		return nil, nil
	}
	priv, err := update.ParsePrivateKey(sh.Key)
	if err != nil {
		return nil, fmt.Errorf("share: key_file: %w", err)
	}
	peers := map[string]ed25519.PublicKey{}
	for name, key := range sh.Peers {
		if peers[name], err = update.ParsePublicKey(key); err != nil {
			return nil, fmt.Errorf("share: peer %s: %w", name, err)
		}
		if peers[name].Equal(priv.Public()) {
			return nil, fmt.Errorf("share: peer %s has this server's own key", name)
		}
	}
	for _, b := range sh.Backends {
		if blocks.Backend(b) == nil {
			return nil, fmt.Errorf("share: backend %q is not in block.backends", b)
		}
	}
	var store share.Store = &share.GitHub{API: sh.API, Repo: sh.Repo, Branch: sh.Branch, Token: sh.Token, HTTP: &http.Client{Timeout: 30 * time.Second}}
	if sh.SSHKey != nil {
		store = &share.Git{URL: "git@github.com:" + sh.Repo + ".git", Branch: sh.Branch, Key: sh.SSHKey, Name: sh.Name,
			Dir: filepath.Join(cfg.DataDir, "share-git")}
	}
	return &share.Syncer{Name: sh.Name, Key: priv, Peers: peers, Blocks: blocks, Backends: sh.Backends, Apply: sh.Apply,
		Store:     store,
		Allowed:   func(ip string) bool { return allowed(pol, ip) },
		StateFile: filepath.Join(cfg.DataDir, "share.json"), Log: log}, nil
}

// accessLine is one access log line of a site, for the auto-ban.
type accessLine struct {
	site string
	r    visitors.Request
}

// runAutoban applies the auto-ban's decisions on WAF events and access log
// lines: it blocks through the configured backends, or only records them
// in dry-run mode.
func runAutoban(ctx context.Context, ban *autoban.Engine, blocks *block.Manager, pol *policy.Manager,
	in <-chan event.Event, lines <-chan accessLine, ws *web.Server, notice func(string, string), log *slog.Logger) {
	for {
		var d *autoban.Decision
		select {
		case <-ctx.Done():
			return
		case ev := <-in:
			d = ban.Process(ev)
		case l := <-lines:
			d = ban.Access(l.site, l.r)
		}
		if d == nil {
			continue
		}
		until := "until unblocked"
		if d.Duration > 0 {
			until = "for " + config.Duration(d.Duration).String()
		}
		reason := fmt.Sprintf("auto-ban #%d: %s", d.Offence, d.Reason)
		switch _, blocked := blocks.Lookup(d.IP); {
		case blocked:
			d.Result = "skipped: already blocked"
		case allowed(pol, d.IP):
			d.Result = "skipped: on the allow list"
		default:
			if _, err := blocks.Normalize(d.IP, ""); err != nil {
				d.Result = "skipped: " + err.Error()
				break
			}
			if d.DryRun {
				d.Result = "would block"
				break
			}
			s := ban.Settings()
			via := "autoban"
			if d.Rule.Trap > 0 {
				via = "trap"
			}
			rule := d.Rule
			e := block.Entry{IP: d.IP, Backends: s.Backends, By: "autoban", Via: via, Reason: reason, At: time.Now(), Site: d.Site, Rule: &rule}
			if d.Duration > 0 {
				e.Expires = e.At.Add(d.Duration)
			}
			cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			err := blocks.Block(cctx, e)
			cancel()
			if err != nil {
				d.Result = "error: " + err.Error()
				log.Error("autoban", "ip", d.IP, "err", err)
			} else {
				d.Result = "blocked"
			}
		}
		if err := ban.Record(*d); err != nil {
			log.Error("autoban: save", "err", err)
		}
		if strings.HasPrefix(d.Result, "skipped") {
			continue
		}
		ws.Audit().Log("autoban", "", "block.auto", fmt.Sprintf("%s %s %s: %s — %s", d.IP, until, d.Site, d.Reason, d.Result))
		mode := ""
		if d.DryRun {
			mode = " (dry run, nothing blocked)"
		}
		notice("warning", fmt.Sprintf("Auto-ban%s: %s %s\n%s\nSite: %s · offence #%d · %s", mode, d.IP, until, d.Reason, d.Site, d.Offence, d.Result))
	}
}

func allowed(pol *policy.Manager, ip string) bool {
	st := pol.State()
	_, ok := st.AllowedFor(ip)
	return ok
}

// checkHealth looks every five minutes at what an update of ISPmanager or
// nginx could break: the include of the panel's rules, and the rule files.
// It rewrites missing rule files but never edits nginx's config; it warns.
func checkHealth(ctx context.Context, cfg *config.Config, pol *policy.Manager, h *web.Health, notice func(string, string), log *slog.Logger) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	reported := ""
	for {
		problems := pol.CheckInclude(cfg.Nginx.IncludeFile)
		if len(problems) > 0 {
			cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			if err := pol.Apply(cctx); err != nil {
				problems = append(problems, "writing the rules again: "+err.Error())
			}
			cancel()
		}
		h.Set(problems)
		key := strings.Join(problems, "\n")
		if key != reported {
			if len(problems) > 0 {
				log.Error("health", "problems", problems)
				notice("critical", "WAFISP Panel: the panel's rules may not apply\n"+key)
			} else if reported != "" {
				notice("info", "WAFISP Panel: the panel's rules are loaded again")
			}
			reported = key
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func newPolicy(cfg *config.Config, log *slog.Logger) *policy.Manager {
	return &policy.Manager{
		File: filepath.Join(cfg.DataDir, "policy.json"), Dir: cfg.ModSec.RulesDir,
		Test: cfg.Nginx.Test, Reload: cfg.Nginx.Reload, MinAvailMB: cfg.Nginx.MinAvailMB,
		Run: policy.Exec, Log: log,
	}
}

func newBlocks(cfg *config.Config, pol *policy.Manager, log *slog.Logger) (*block.Manager, error) {
	m := &block.Manager{File: filepath.Join(cfg.DataDir, "blocks.json"), Log: log}
	for _, p := range cfg.Block.Protected {
		pr, err := config.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		m.Protected = append(m.Protected, pr)
	}
	// The host's own addresses are never blocked either, nor Cloudflare's.
	m.Protected = append(m.Protected, localPrefixes()...)
	if !cfg.Block.BlockCloudflare {
		m.Protected = append(m.Protected, block.Cloudflare...)
	}
	for _, b := range cfg.Block.Backends {
		switch b {
		case "ipset":
			m.Backends = append(m.Backends, &block.IPSet{Set: cfg.Block.IPSet, Ports: cfg.Block.Ports, Run: policy.Exec})
		case "modsec":
			m.Backends = append(m.Backends, &block.ModSec{Policy: pol})
		case "ispmgr":
			m.Backends = append(m.Backends, &block.ISPmgr{Mgrctl: cfg.Block.Mgrctl, Comment: "wafisp-panel", Run: policy.Exec})
		}
	}
	return m, nil
}

func localPrefixes() []netip.Prefix {
	var out []netip.Prefix
	ifs, _ := netInterfaceAddrs()
	for _, a := range ifs {
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out
}

// runCheck reads everything the panel would read and prints what it found,
// without starting anything or changing files, nginx or the firewall.
func runCheck(cfg *config.Config) error {
	fmt.Println("config OK")
	files, err := filepath.Glob(cfg.ModSec.AuditGlob)
	if err != nil {
		return err
	}
	fmt.Printf("audit logs: %d files match %s\n", len(files), cfg.ModSec.AuditGlob)
	total := 0
	for _, f := range files {
		n, denied, err := countFile(f)
		if err != nil {
			fmt.Printf("  %-40s ERROR %v\n", filepath.Base(f), err)
			continue
		}
		total += n
		if n > 0 {
			fmt.Printf("  %-40s %6d events, %d denied\n", filepath.Base(f), n, denied)
		}
	}
	fmt.Printf("events in the current logs: %d\n", total)

	sr := &sites.Reader{VhostsDir: cfg.Nginx.VhostsDir, ResourcesDir: cfg.Nginx.ResourcesDir}
	modes := map[string]int{}
	for _, s := range sr.Sites() {
		modes[s.WAF]++
	}
	fmt.Printf("sites: %d, WAF modes: %v\n", len(sr.Sites()), modes)

	pol := newPolicy(cfg, slog.New(slog.DiscardHandler))
	if err := pol.Load(); err != nil {
		return err
	}
	st := pol.State()
	before, after := st.Files(cfg.ModSec.RulesDir)
	fmt.Printf("panel rules dir %s: before.conf %d lines, after.conf %d lines, %d allowed, %d denied, %d exclusions\n",
		cfg.ModSec.RulesDir, strings.Count(before, "\n"), strings.Count(after, "\n"), len(st.Allow), len(st.Deny), len(st.Exclusions))
	notLoaded := cfg.Nginx.IncludeFile == "none"
	if notLoaded {
		fmt.Println("nginx include: none (nginx does not load the panel's rules)")
	} else {
		for _, p := range pol.CheckInclude(cfg.Nginx.IncludeFile) {
			if !strings.Contains(p, "is missing") {
				fmt.Println("WARNING:", p)
				notLoaded = true
			}
		}
	}
	if notLoaded {
		fmt.Println("WARNING: the modsec backend, the allow list, site modes and exclusions have no effect until nginx loads the panel's rules (docs/DEPLOYMENT.md)")
	}
	fmt.Printf("block backends: %s (default %s), protected: %s\n", strings.Join(cfg.Block.Backends, ", "),
		strings.Join(cfg.Block.Default, ", "), strings.Join(cfg.Block.Protected, ", "))
	return nil
}

func countFile(path string) (n, denied int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	p := &modsec.Parser{}
	r := bufio.NewReaderSize(f, 256<<10)
	for {
		line, err := r.ReadString('\n')
		if ev := p.Feed(strings.TrimRight(line, "\r\n")); ev != nil {
			n++
			if ev.Denied {
				denied++
			}
		}
		if err != nil {
			break
		}
	}
	return n, denied, nil
}

// runParse prints a summary of one audit log: for checking the parser on a
// host before the panel starts.
func runParse(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	site := strings.TrimSuffix(filepath.Base(path), ".audit.log")
	p := &modsec.Parser{Site: site}
	r := bufio.NewReaderSize(f, 256<<10)
	n, denied, noRules := 0, 0, 0
	cats, ruleIDs := map[string]int{}, map[string]int{}
	for {
		line, err := r.ReadString('\n')
		if ev := p.Feed(strings.TrimRight(line, "\r\n")); ev != nil {
			n++
			if ev.Denied {
				denied++
			}
			if len(ev.RuleIDs()) == 0 {
				noRules++
			}
			cats[ev.Category]++
			for _, id := range ev.RuleIDs() {
				ruleIDs[id]++
			}
			if n <= 5 {
				fmt.Printf("%s %s %s %s %s%s status=%d score=%d %s rules=%v %q\n", ev.Time.Format(time.DateTime), ev.ID, ev.SrcIP,
					ev.Method, ev.Host, cut(ev.URI, 60), ev.Status, ev.Score, ev.ActionName(), ev.RuleIDs(), cut(ev.Reason(), 60))
			}
		}
		if err != nil {
			break
		}
	}
	fmt.Printf("\n%d events, %d denied, %d without attack rules\nclasses: %v\n", n, denied, noRules, cats)
	type kv struct {
		k string
		v int
	}
	var top []kv
	for k, v := range ruleIDs {
		top = append(top, kv{k, v})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].v > top[j].v })
	if len(top) > 15 {
		top = top[:15]
	}
	fmt.Printf("top rules: %v\n", top)
	return nil
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func runTestChannel(ctx context.Context, cfg *config.Config, name string, hc *http.Client) error {
	i := slices.IndexFunc(cfg.Channels, func(c config.Channel) bool { return c.Name == name })
	if i < 0 {
		return fmt.Errorf("no channel named %q", name)
	}
	s, err := notify.NewSender(cfg.Channels[i], hc)
	if err != nil {
		return err
	}
	now := time.Now()
	ev := event.Event{ID: "test", Site: "example.com", SrcIP: "203.0.113.10", Host: "example.com", URI: "/login?id=1'+or+1=1--",
		Category: "sqli", Denied: true, Score: 10, Country: "Test", Time: now,
		Rules: []event.Match{{ID: "942100", Msg: "SQL Injection Attack Detected via libinjection", Severity: 2}}}
	a := rules.Alert{Rule: "test", Severity: "info", GroupBy: "src_ip", GroupKey: ev.SrcIP, Count: 1,
		First: now, Last: now, Denied: 1, Hosts: []string{ev.Host}, Types: []string{"sqli"}, Samples: []event.Event{ev}}
	if err := s.Send(ctx, a); err != nil {
		return err
	}
	fmt.Println("test alert sent to", name)
	return nil
}

func serveHTTP(ctx context.Context, addr string, st *stats.Registry, maxAge time.Duration, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !st.Healthy(maxAge) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		st.WriteJSON(w)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		st.WritePrometheus(w)
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("http server", "err", err)
	}
}

// loadRules prefers the rules saved in the panel over the config file.
func loadRules(cfg *config.Config, file string) ([]config.Rule, error) {
	b, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return cfg.Rules, nil
	}
	if err != nil {
		return nil, err
	}
	var rs []config.Rule
	if err := yaml.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if err := cfg.ValidateRules(rs); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return rs, nil
}

func runResetPassword(cfgPath, name string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	users, err := auth.OpenUsers(filepath.Join(cfg.DataDir, "users.json"))
	if err != nil {
		return err
	}
	pw := auth.RandomPassword()
	if err := users.SetPassword(name, pw); err != nil {
		return err
	}
	fmt.Printf("new password for %s: %s\n", name, pw)
	return nil
}

// releaseKey is the public half of the release signing key; the private
// half stays on the maintainer's machine (make release signs with it).
func releaseKey() ed25519.PublicKey {
	k, err := update.ParsePublicKey(update.ReleaseKey)
	if err != nil {
		panic(err)
	}
	return k
}

// runSigning makes a key (-genkey) or signs release files (-sign).
func runSigning(keyPath, signWith string, files []string) error {
	if keyPath != "" {
		if _, err := os.Stat(keyPath); err == nil {
			return fmt.Errorf("%s exists; not overwriting a signing key", keyPath)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
		return nil
	}
	raw, err := os.ReadFile(signWith)
	if err != nil {
		return err
	}
	priv, err := update.ParsePrivateKey(string(raw))
	if err != nil {
		return err
	}
	if !priv.Public().(ed25519.PublicKey).Equal(releaseKey()) {
		return errors.New("this key does not match the public key built into the panel")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if err := os.WriteFile(f+".sig", update.Sign(priv, data), 0o644); err != nil {
			return err
		}
		fmt.Println("signed", f)
	}
	return nil
}

// runInstaller is the one-shot unit started by the panel: it swaps the
// binary, restarts the service and rolls back when the new one fails.
func runInstaller(cfgPath, staged string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	in := &update.Installer{Exe: exe, Dir: filepath.Join(cfg.DataDir, "update"), Service: "wafisp", PublicKey: releaseKey(),
		From: version, HTTP: &http.Client{Timeout: 5 * time.Second}, Wait: 90 * time.Second, Every: 3 * time.Second}
	if cfg.HTTP.Listen != "" {
		in.Healthz = "http://" + cfg.HTTP.Listen + "/healthz"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	time.Sleep(2 * time.Second) // let the panel answer the click before it restarts
	if staged == "" {
		return in.Rollback(ctx)
	}
	return in.Install(ctx, staged)
}
