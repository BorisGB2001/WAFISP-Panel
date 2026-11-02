package siem

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strconv"
	"time"

	"wafisp/internal/config"
	"wafisp/internal/event"
	"wafisp/internal/stats"
)

// maxUDP keeps a datagram below the usual 64 KiB limit.
const maxUDP = 60000

// Syslog sends RFC 5424 messages to one receiver. Events are queued and
// written by one goroutine that reconnects on failure; when the receiver is
// down for long the queue fills up and events are dropped and counted
// rather than blocking alerting.
type Syslog struct {
	cfg      config.SIEM
	log      *slog.Logger
	stats    *stats.Registry
	hostname string
	tls      *tls.Config

	q    chan []byte
	conn net.Conn
}

func NewSyslog(cfg config.SIEM, log *slog.Logger, st *stats.Registry) (*Syslog, error) {
	s := &Syslog{cfg: cfg, log: log, stats: st, hostname: cfg.Hostname}
	if s.hostname == "" {
		s.hostname, _ = os.Hostname()
	}
	if cfg.Network == "tls" {
		host, _, err := net.SplitHostPort(cfg.Address)
		if err != nil {
			return nil, fmt.Errorf("siem %s: %w", cfg.Name, err)
		}
		s.tls = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("siem %s: %w", cfg.Name, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("siem %s: ca_file has no PEM certificate", cfg.Name)
			}
			s.tls.RootCAs = pool
		}
	}
	return s, nil
}

// Wants reports whether the target is configured to receive ev.
func (s *Syslog) Wants(ev event.Event) bool {
	if s.cfg.OnlyDenied && !ev.Denied {
		return false
	}
	return len(s.cfg.Sites) == 0 || slices.Contains(s.cfg.Sites, ev.Site)
}

func (s *Syslog) Enqueue(ev event.Event) {
	if !s.Wants(ev) {
		return
	}
	select {
	case s.q <- s.message(ev):
	default:
		s.stats.Add(fmt.Sprintf("siem_dropped_total{target=%q}", s.cfg.Name), 1)
	}
}

func (s *Syslog) Start(ctx context.Context) {
	s.q = make(chan []byte, s.cfg.QueueSize)
	go func() {
		defer func() {
			if s.conn != nil {
				s.conn.Close()
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-s.q:
				s.write(ctx, m)
			}
		}
	}()
}

// write retries one message until it is sent or ctx ends.
func (s *Syslog) write(ctx context.Context, m []byte) {
	backoff := time.Second
	for {
		if s.conn == nil {
			c, err := s.dial(ctx)
			if err != nil {
				s.log.Warn("siem connect failed", "target", s.cfg.Name, "err", err, "retry_in", backoff)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff = min(backoff*2, time.Minute)
				continue
			}
			s.conn = c
		}
		s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := s.conn.Write(m); err != nil {
			s.log.Warn("siem write failed, reconnecting", "target", s.cfg.Name, "err", err)
			s.conn.Close()
			s.conn = nil
			continue
		}
		s.stats.Add(fmt.Sprintf("siem_sent_total{target=%q}", s.cfg.Name), 1)
		return
	}
}

func (s *Syslog) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	switch s.cfg.Network {
	case "tls":
		return (&tls.Dialer{NetDialer: d, Config: s.tls}).DialContext(ctx, "tcp", s.cfg.Address)
	default:
		return d.DialContext(ctx, s.cfg.Network, s.cfg.Address)
	}
}

// message builds a framed RFC 5424 message.
func (s *Syslog) message(ev event.Event) []byte {
	sev := 5 // notice
	if ev.Denied {
		sev = 4 // warning
	}
	body := CEF(ev)
	if s.cfg.Format == "json" {
		body = JSON(ev, s.cfg.JSONRaw)
	}
	ts := ev.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	line := body
	if s.cfg.Header == "rfc5424" {
		line = fmt.Sprintf("<%d>1 %s %s %s - %s - %s",
			s.cfg.Facility*8+sev, ts.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
			nilValue(s.hostname), nilValue(s.cfg.AppName), "waf-event", body)
	}

	switch {
	case s.cfg.Network == "udp":
		if len(line) > maxUDP {
			line = line[:maxUDP]
		}
		return []byte(line)
	case s.cfg.Framing == "octet":
		return []byte(strconv.Itoa(len(line)) + " " + line)
	default:
		return []byte(line + "\n")
	}
}

func nilValue(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
