package ua

import "testing"

func TestParse(t *testing.T) {
	for s, want := range map[string]Info{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36":                             {Kind: Browser, OS: "Windows", Browser: "Chrome", Device: Desktop},
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:158.0) Gecko/20100101 Firefox/158.0":                                                    {Kind: Browser, OS: "macOS", Browser: "Firefox", Device: Desktop},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1": {Kind: Browser, OS: "iOS", Browser: "Safari", Device: Mobile},
		"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1":          {Kind: Browser, OS: "iOS", Browser: "Safari", Device: Tablet},
		"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Mobile Safari/537.36":                      {Kind: Browser, OS: "Android", Browser: "Chrome", Device: Mobile},
		"Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36":                              {Kind: Browser, OS: "Android", Browser: "Chrome", Device: Tablet},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 YaBrowser/25.8 Safari/537.36":              {Kind: Browser, OS: "Windows", Browser: "Yandex Browser", Device: Desktop},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 Edg/140.0":                   {Kind: Browser, OS: "Windows", Browser: "Edge", Device: Desktop},
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":                                                                {Kind: Bot, Name: "Googlebot", Good: true, Device: Bot},
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)":                                                                        {Kind: Bot, Name: "YandexBot", Good: true, Device: Bot},
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)":                                                                      {Kind: Bot, Name: "AhrefsBot", Device: Bot},
		"Mozilla/5.0 (compatible; SomeNewCrawler/1.0)":                                                                                            {Kind: Bot, Name: "Other bot", Device: Bot},
		"curl/8.5.0":                             {Kind: Script, Name: "curl", Device: Script},
		"python-requests/2.32.3":                 {Kind: Script, Name: "python-requests", Device: Script},
		"Go-http-client/1.1":                     {Kind: Script, Name: "Go http client", Device: Script},
		"sqlmap/1.8#stable (https://sqlmap.org)": {Kind: Script, Name: "sqlmap", Device: Script},
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0 Safari/537.36": {Kind: Script, Name: "Headless Chrome", Device: Script},
		"zgrab/0.x":   {Kind: Script, Name: "zgrab", Device: Script},
		"Hello World": {Kind: Script, Name: "Other", Device: Script},
		"":            {Kind: Empty, Device: Empty},
		"-":           {Kind: Empty, Device: Empty},
	} {
		if got := Parse(s); got != want {
			t.Errorf("%q:\n got %+v\nwant %+v", s, got, want)
		}
	}
}

func TestRefererSource(t *testing.T) {
	for ref, want := range map[string]Source{
		"":                                    {Kind: Direct},
		"-":                                   {Kind: Direct},
		"https://www.google.com/":             {Search, "Google", "google.com"},
		"https://www.google.ru/search?q=x":    {Search, "Google", "google.ru"},
		"https://yandex.ru/search/?text=x":    {Search, "Yandex", "yandex.ru"},
		"https://ya.ru/":                      {Search, "Yandex", "ya.ru"},
		"https://www.bing.com/":               {Search, "Bing / MSN", "bing.com"},
		"https://www.msn.com/ru-ru/feed":      {Search, "Bing / MSN", "msn.com"},
		"https://go.mail.ru/search?q=x":       {Search, "Mail.ru", "go.mail.ru"},
		"https://duckduckgo.com/":             {Search, "DuckDuckGo", "duckduckgo.com"},
		"https://m.vk.com/away.php":           {Social, "VK", "m.vk.com"},
		"https://t.me/channel/1":              {Social, "Telegram", "t.me"},
		"https://myvk.com/":                   {Other, "myvk.com", "myvk.com"},
		"https://notgoogle.com/":              {Other, "notgoogle.com", "notgoogle.com"},
		"https://shop.example.ru/cart":        {Internal, "shop.example.ru", "shop.example.ru"},
		"https://www.shop.example.ru/":        {Internal, "shop.example.ru", "shop.example.ru"},
		"https://partner.example.org/catalog": {Other, "partner.example.org", "partner.example.org"},
	} {
		if got := RefererSource(ref, "shop.example.ru"); got != want {
			t.Errorf("%q: got %+v want %+v", ref, got, want)
		}
	}
}
