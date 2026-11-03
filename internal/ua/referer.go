package ua

import (
	"net/url"
	"strings"
)

// Kinds of traffic sources.
const (
	Direct   = "direct"   // no Referer
	Internal = "internal" // from the same site
	Search   = "search"
	Social   = "social"
	Other    = "other" // another site
)

// Source is where a visit came from.
type Source struct {
	Kind   string
	Name   string // the search engine or network ("Yandex", "VK"); the domain for Other
	Domain string // the referring host without www.; "" for Direct
}

var engines = []struct{ match, name string }{
	{"google.", "Google"}, {"yandex.", "Yandex"}, {"ya.ru", "Yandex"}, {"bing.com", "Bing / MSN"}, {"msn.com", "Bing / MSN"},
	{"go.mail.ru", "Mail.ru"}, {"search.mail.ru", "Mail.ru"}, {"duckduckgo.com", "DuckDuckGo"}, {"yahoo.", "Yahoo"},
	{"baidu.com", "Baidu"}, {"rambler.ru", "Rambler"}, {"ecosia.org", "Ecosia"}, {"search.brave.com", "Brave"},
	{"perplexity.ai", "Perplexity"}, {"chatgpt.com", "ChatGPT"}, {"seznam.cz", "Seznam"},
}

var networks = []struct{ match, name string }{
	{"vk.com", "VK"}, {"vk.ru", "VK"}, {"vkvideo.ru", "VK"}, {"t.me", "Telegram"}, {"telegram.org", "Telegram"}, {"ok.ru", "OK"},
	{"dzen.ru", "Dzen"}, {"facebook.com", "Facebook"}, {"fb.com", "Facebook"}, {"instagram.com", "Instagram"},
	{"youtube.com", "YouTube"}, {"youtu.be", "YouTube"}, {"twitter.com", "X"}, {"x.com", "X"}, {"t.co", "X"},
	{"linkedin.com", "LinkedIn"}, {"whatsapp.com", "WhatsApp"}, {"pinterest.", "Pinterest"}, {"reddit.com", "Reddit"},
	{"tiktok.com", "TikTok"}, {"max.ru", "Max"},
}

// RefererSource classifies a Referer header for a request to site.
func RefererSource(ref, site string) Source {
	ref = strings.TrimSpace(ref)
	if ref == "" || ref == "-" {
		return Source{Kind: Direct}
	}
	u, err := url.Parse(ref)
	if err != nil || u.Hostname() == "" {
		return Source{Kind: Direct}
	}
	host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	site = strings.TrimPrefix(strings.ToLower(site), "www.")
	if host == site || strings.HasSuffix(host, "."+site) {
		return Source{Kind: Internal, Name: host, Domain: host}
	}
	for _, e := range engines {
		if hostMatches(host, e.match) {
			return Source{Kind: Search, Name: e.name, Domain: host}
		}
	}
	for _, n := range networks {
		if hostMatches(host, n.match) {
			return Source{Kind: Social, Name: n.name, Domain: host}
		}
	}
	return Source{Kind: Other, Name: host, Domain: host}
}

// hostMatches matches "vk.com" against vk.com and m.vk.com, and "google."
// against google.ru and www.google.com.br, but never inside a label
// (myvk.com, notgoogle.com).
func hostMatches(host, m string) bool {
	if strings.HasSuffix(m, ".") {
		return strings.HasPrefix(host, m) || strings.Contains(host, "."+m)
	}
	return host == m || strings.HasSuffix(host, "."+m)
}
