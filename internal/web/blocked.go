package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"wafisp/internal/block"
	"wafisp/internal/policy"
	"wafisp/internal/store"
)

type blockedRow struct {
	block.Entry
	// Hits are requests from the address since it was blocked: the
	// modsec backend still logs them; ipset drops them before nginx.
	Hits int
}

// blockedPage lists every block with its actions: change the time, move
// the address to the allow list, unblock.
func (s *Server) blockedPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	by := r.URL.Query().Get("by")
	var rows []blockedRow
	idx := map[string]int{}
	oldest := time.Now()
	for _, e := range s.Blocks.Entries() {
		if q != "" && !strings.Contains(e.IP, q) && !strings.Contains(strings.ToLower(e.Reason), strings.ToLower(q)) && !strings.Contains(e.Site, q) {
			continue
		}
		if (by == "autoban" && e.By != "autoban") || (by == "people" && e.By == "autoban") {
			continue
		}
		idx[e.IP] = len(rows)
		rows = append(rows, blockedRow{Entry: e})
		if e.At.Before(oldest) {
			oldest = e.At
		}
	}
	s.Store.Scan(oldest, func(e *store.Summary) bool {
		if i, ok := idx[e.SrcIP]; ok && e.Time.After(rows[i].At) {
			rows[i].Hits++
		}
		return true
	})
	auto := 0
	for _, e := range s.Blocks.Entries() {
		if e.By == "autoban" {
			auto++
		}
	}
	s.render(w, r, rc, "blocked.html", page{Title: "Blocked addresses", Active: "blocked", Data: map[string]any{
		"Rows": rows, "Q": q, "By": by, "TTLs": blockTTLs, "Total": len(s.Blocks.Entries()), "Auto": auto,
	}})
}

// blockExpiry sets a new block time, counted from now.
func (s *Server) blockExpiry(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	to := back(r, "/blocked")
	ip := r.FormValue("ip")
	ttl, ok := ttlOf(r.FormValue("ttl"))
	if !ok {
		flashRedirect(w, r, to, "", tr(r, "Unknown block duration"))
		return
	}
	var exp time.Time
	if ttl.D > 0 {
		exp = time.Now().Add(ttl.D)
	}
	if err := s.Blocks.SetExpiry(ip, exp); err != nil {
		flashRedirect(w, r, to, "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "block.expiry", fmt.Sprintf("%s → %s", ip, ttl.Label))
	flashRedirect(w, r, to, tr(r, "%s is now blocked for %s", ip, tr(r, ttl.Label)), "")
}

// blockToAllow unblocks an address and puts it on the allow list: for a
// trusted source that was blocked by mistake.
func (s *Server) blockToAllow(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	to := back(r, "/blocked")
	ip := r.FormValue("ip")
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		flashRedirect(w, r, to, "", tr(r, "Give a reason — it goes to the audit log"))
		return
	}
	allowIP, err := s.Blocks.NormalizeAllow(ip)
	if err != nil {
		flashRedirect(w, r, to, "", errText(r, err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if err := s.Blocks.Unblock(ctx, ip); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "unblock.failed", ip+" — "+err.Error())
		flashRedirect(w, r, to, "", tr(r, "The unblock did not go through everywhere: %s", err))
		return
	}
	err = s.Policy.Update(ctx, func(st *policy.State) error {
		st.Allow = slices.DeleteFunc(st.Allow, func(x policy.Addr) bool { return x.IP == allowIP })
		st.Allow = append(st.Allow, policy.Addr{IP: allowIP, Meta: policy.Meta{By: rc.User.Name, Reason: reason, At: time.Now()}})
		return nil
	})
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "allow.failed", allowIP+" — "+err.Error())
		flashRedirect(w, r, to, "", tr(r, "Unblocked %s, but the allow list was not changed: %s", ip, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "block.to_allow", fmt.Sprintf("%s: %s", allowIP, reason))
	flashRedirect(w, r, to, tr(r, "%s is unblocked and on the allow list", allowIP), "")
}

// search takes an address from the menu's search box: a full address
// opens its page; a subnet or the start of an address opens the attack
// log filtered to it.
func (s *Server) search(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if a, err := netip.ParseAddr(q); err == nil {
		http.Redirect(w, r, "/ip/"+a.Unmap().String(), http.StatusSeeOther)
		return
	}
	if p, err := netip.ParsePrefix(q); err == nil {
		http.Redirect(w, r, "/attacks?period=30d&ip="+url.QueryEscape(p.Masked().String()), http.StatusSeeOther)
		return
	}
	if q == "" || strings.Trim(q, "0123456789abcdefABCDEF.:") != "" {
		flashRedirect(w, r, "/attacks", "", tr(r, "Type an IP address, a subnet or the start of an address"))
		return
	}
	http.Redirect(w, r, "/attacks?period=30d&ip="+url.QueryEscape(q+"*"), http.StatusSeeOther)
}
