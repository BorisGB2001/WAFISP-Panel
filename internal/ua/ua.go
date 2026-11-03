// Package ua tells from a User-Agent header what sent a request: a browser
// (with its OS, browser and device), a search engine or other bot, or a
// script or scanner. It matches known tokens; no external database.
package ua

import "strings"

// Kinds of clients.
const (
	Browser = "browser"
	Bot     = "bot"
	Script  = "script"
	Empty   = "empty"
)

// Devices.
const (
	Desktop = "desktop"
	Mobile  = "mobile"
	Tablet  = "tablet"
)

// Info is what a User-Agent says.
type Info struct {
	Kind    string // browser | bot | script | empty
	Name    string // the bot or script ("Googlebot", "curl"); empty for browsers
	Good    bool   // a search engine or a well-known service bot
	OS      string // browsers: Windows, macOS, Android, iOS, Linux, ChromeOS, Other
	Browser string // browsers: Chrome, Firefox, Safari, Edge, Yandex Browser, ...
	Device  string // browsers: desktop | mobile | tablet; else the kind
}

type token struct {
	needle, name string
	good         bool
}

// bots are matched in order, case-insensitively.
var bots = []token{
	{"googlebot", "Googlebot", true}, {"google-inspectiontool", "Googlebot", true}, {"adsbot-google", "Googlebot", true},
	{"mediapartners-google", "Googlebot", true}, {"googleother", "Googlebot", true},
	{"yandexbot", "YandexBot", true}, {"yandexmobilebot", "YandexBot", true}, {"yandex.com/bots", "YandexBot", true},
	{"bingbot", "Bingbot", true}, {"bingpreview", "Bingbot", true}, {"msnbot", "Bingbot", true},
	{"duckduckbot", "DuckDuckBot", true}, {"applebot", "Applebot", true}, {"baiduspider", "Baiduspider", true},
	{"mail.ru_bot", "Mail.ru bot", true}, {"seznambot", "SeznamBot", true}, {"petalbot", "PetalBot", true},
	{"facebookexternalhit", "Facebook", true}, {"meta-externalagent", "Facebook", true}, {"twitterbot", "Twitterbot", true},
	{"telegrambot", "TelegramBot", true}, {"vkshare", "VK", true}, {"whatsapp", "WhatsApp", true}, {"slackbot", "Slackbot", true},
	{"gptbot", "GPTBot", false}, {"chatgpt-user", "ChatGPT", false}, {"oai-searchbot", "OpenAI", false}, {"claudebot", "ClaudeBot", false},
	{"claude-user", "Claude", false}, {"perplexitybot", "PerplexityBot", false}, {"bytespider", "Bytespider", false},
	{"ahrefsbot", "AhrefsBot", false}, {"semrushbot", "SemrushBot", false}, {"mj12bot", "MJ12bot", false}, {"dotbot", "DotBot", false},
	{"dataforseobot", "DataForSeoBot", false}, {"blexbot", "BLEXBot", false}, {"amazonbot", "Amazonbot", false},
	{"censysinspect", "Censys", false}, {"expanse", "Palo Alto Expanse", false}, {"internet-measurement", "Internet measurement", false},
	{"uptimerobot", "UptimeRobot", true},
}

// scripts are HTTP libraries, tools and scanners.
var scripts = []token{
	{"sqlmap", "sqlmap", false}, {"nikto", "Nikto", false}, {"nuclei", "Nuclei", false}, {"nmap", "Nmap", false},
	{"masscan", "masscan", false}, {"zgrab", "zgrab", false}, {"wpscan", "WPScan", false}, {"dirbuster", "DirBuster", false},
	{"gobuster", "gobuster", false}, {"ffuf", "ffuf", false}, {"acunetix", "Acunetix", false}, {"nessus", "Nessus", false},
	{"headlesschrome", "Headless Chrome", false}, {"phantomjs", "PhantomJS", false}, {"scrapy", "Scrapy", false},
	{"python-requests", "python-requests", false}, {"python-urllib", "Python urllib", false}, {"aiohttp", "aiohttp", false},
	{"python-httpx", "httpx", false}, {"httpx", "httpx", false}, {"curl/", "curl", false}, {"wget", "Wget", false},
	{"go-http-client", "Go http client", false}, {"okhttp", "OkHttp", false}, {"java/", "Java", false},
	{"apache-httpclient", "Apache HttpClient", false}, {"libwww-perl", "libwww-perl", false}, {"guzzlehttp", "Guzzle", false},
	{"axios", "axios", false}, {"node-fetch", "node-fetch", false}, {"undici", "Node.js", false}, {"postmanruntime", "Postman", false},
	{"winhttp", "WinHTTP", false}, {"powershell", "PowerShell", false}, {"php/", "PHP", false},
}

// Parse reads a User-Agent header.
func Parse(s string) Info {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return Info{Kind: Empty, Device: Empty}
	}
	l := strings.ToLower(s)
	for _, t := range bots {
		if strings.Contains(l, t.needle) {
			return Info{Kind: Bot, Name: t.name, Good: t.good, Device: Bot}
		}
	}
	for _, t := range scripts {
		if strings.Contains(l, t.needle) {
			return Info{Kind: Script, Name: t.name, Device: Script}
		}
	}
	if strings.Contains(l, "bot") || strings.Contains(l, "crawler") || strings.Contains(l, "spider") || strings.Contains(l, "+http") {
		return Info{Kind: Bot, Name: "Other bot", Device: Bot}
	}
	if !strings.HasPrefix(l, "mozilla/") && !strings.HasPrefix(l, "opera/") {
		return Info{Kind: Script, Name: "Other", Device: Script}
	}
	return Info{Kind: Browser, OS: osOf(l), Browser: browserOf(l), Device: deviceOf(l)}
}

func osOf(l string) string {
	switch {
	case strings.Contains(l, "windows"):
		return "Windows"
	case strings.Contains(l, "android"):
		return "Android"
	case strings.Contains(l, "iphone"), strings.Contains(l, "ipad"), strings.Contains(l, "ipod"):
		return "iOS"
	case strings.Contains(l, "cros"):
		return "ChromeOS"
	case strings.Contains(l, "mac os x"), strings.Contains(l, "macintosh"):
		return "macOS"
	case strings.Contains(l, "linux"), strings.Contains(l, "x11"):
		return "Linux"
	}
	return "Other"
}

func browserOf(l string) string {
	switch {
	case strings.Contains(l, "yabrowser"), strings.Contains(l, "yasearchbrowser"):
		return "Yandex Browser"
	case strings.Contains(l, "edg/"), strings.Contains(l, "edga/"), strings.Contains(l, "edgios/"):
		return "Edge"
	case strings.Contains(l, "opr/"), strings.Contains(l, "opera"):
		return "Opera"
	case strings.Contains(l, "samsungbrowser"):
		return "Samsung Internet"
	case strings.Contains(l, "firefox/"), strings.Contains(l, "fxios/"):
		return "Firefox"
	case strings.Contains(l, "crios/"), strings.Contains(l, "chrome/"):
		return "Chrome"
	case strings.Contains(l, "safari/"):
		return "Safari"
	case strings.Contains(l, "msie"), strings.Contains(l, "trident/"):
		return "Internet Explorer"
	}
	return "Other"
}

func deviceOf(l string) string {
	switch {
	case strings.Contains(l, "ipad"), strings.Contains(l, "tablet"), strings.Contains(l, "android") && !strings.Contains(l, "mobile"):
		return Tablet
	case strings.Contains(l, "mobile"), strings.Contains(l, "iphone"), strings.Contains(l, "ipod"), strings.Contains(l, "android"):
		return Mobile
	}
	return Desktop
}

// Label is a short text for a list: "Googlebot", "curl", "Chrome · Android".
func (i Info) Label() string {
	switch i.Kind {
	case Browser:
		return i.Browser + " · " + i.OS
	case Empty:
		return "no User-Agent"
	}
	return i.Name
}
