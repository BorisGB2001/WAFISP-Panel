package visitors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	chrome    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
	iphone    = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
	googlebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

func line(t time.Time, ip, req string, status int, ref, agent string) string {
	return fmt.Sprintf("%s - - [%s] \"%s\" %d 512 \"%s\" \"%s\"\n", ip, t.Format("02/Jan/2006:15:04:05 -0700"), req, status, ref, agent)
}

func TestParseLine(t *testing.T) {
	r, ok := ParseLine(`203.0.113.5 - - [03/Nov/2026:02:56:13 +0300] "GET /catalog/item.php?id=5 HTTP/1.1" 200 583 "https://yandex.ru/search/?text=x" "` + chrome + `"`)
	if !ok || r.Method != "GET" || r.Path != "/catalog/item.php" || r.Status != 200 || r.Referer != "https://yandex.ru/search/?text=x" || r.Time.Hour() != 2 {
		t.Fatalf("%+v %v", r, ok)
	}
	if _, ok := ParseLine("garbage"); ok {
		t.Fatal("garbage parsed")
	}
	// A malformed request line still counts, without a path.
	if r, ok := ParseLine(`203.0.113.5 - - [03/Nov/2026:02:56:13 +0300] "\x16\x03\x01" 400 0 "-" "-"`); !ok || r.Status != 400 || r.Path != "" {
		t.Fatalf("%+v %v", r, ok)
	}
}

func TestReaderAndReport(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	os.MkdirAll(logs, 0o755)
	st, err := OpenStore(filepath.Join(dir, "visitors"), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := &Reader{Glob: filepath.Join(logs, "*.access.log"), Suffix: ".access.log", StateFile: filepath.Join(dir, "cursors.json"), Store: st}
	now := time.Now().Truncate(time.Second)
	lp := filepath.Join(logs, "shop.example.ru.access.log")
	var b strings.Builder
	b.WriteString(line(now, "198.51.100.1", "GET / HTTP/1.1", 200, "https://www.google.com/", chrome))
	b.WriteString(line(now, "198.51.100.1", "GET /style.css HTTP/1.1", 200, "https://shop.example.ru/", chrome))
	b.WriteString(line(now, "198.51.100.2", "GET /catalog HTTP/1.1", 200, "https://yandex.ru/search/?text=x", iphone))
	b.WriteString(line(now, "198.51.100.3", "GET /about HTTP/1.1", 200, "https://vk.com/", chrome))
	b.WriteString(line(now, "198.51.100.4", "GET /old-page HTTP/1.1", 404, "https://partner.example.org/", chrome))
	b.WriteString(line(now, "66.249.66.1", "GET /catalog HTTP/1.1", 200, "-", googlebot))
	b.WriteString(line(now, "203.0.113.9", "GET /.env HTTP/1.1", 404, "-", "curl/8.5.0"))
	b.WriteString(`198.51.100.5 - - [` + now.Format("02/Jan/2006:15:04:05 -0700") + `] "GET /half`) // still being written
	os.WriteFile(lp, []byte(b.String()), 0o644)
	r.Poll()

	rep := st.Report(now.Add(-time.Hour), now.Add(time.Minute), "")
	a := rep.Total
	if a.Requests != 7 || a.Views != 3 {
		t.Fatalf("requests %d views %d", a.Requests, a.Views)
	}
	checks := map[string][2]int{
		"status 200": {a.Status["200"], 5}, "status 404": {a.Status["404"], 2},
		"bots": {a.Bot["Googlebot"], 1}, "scripts": {a.Script["curl"], 1},
		"mobile": {a.Device["mobile"], 1}, "desktop": {a.Device["desktop"], 2},
		"google": {a.Search["Google"], 1}, "yandex": {a.Search["Yandex"], 1}, "vk": {a.Social["VK"], 1},
		"404 path": {a.NotFound["/old-page"], 1}, "404 scan": {a.NotFound["/.env"], 1},
		"page": {a.Page["/catalog"], 1}, "css is no page": {a.Page["/style.css"], 0},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s: %d, want %d", name, c[0], c[1])
		}
	}
	if rep.Sites["shop.example.ru"] != 7 || len(rep.Series) == 0 {
		t.Fatalf("sites %v series %v", rep.Sites, rep.Series)
	}

	// The half line is finished later; nothing is counted twice.
	f, _ := os.OpenFile(lp, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(` HTTP/1.1" 200 1 "-" "` + chrome + `"` + "\n")
	f.Close()
	r.Poll()
	if n := st.Report(now.Add(-time.Hour), now.Add(time.Minute), "").Total.Requests; n != 8 {
		t.Fatalf("after append: %d", n)
	}

	// Rotation: the log is replaced by a new, shorter one.
	os.Rename(lp, lp+".1")
	os.WriteFile(lp, []byte(line(now, "198.51.100.6", "GET / HTTP/1.1", 200, "-", chrome)), 0o644)
	r.Poll()
	if n := st.Report(now.Add(-time.Hour), now.Add(time.Minute), "").Total.Requests; n != 9 {
		t.Fatalf("after rotation: %d", n)
	}

	// Everything survives a restart, and the logs can go.
	os.Remove(lp)
	os.Remove(lp + ".1")
	st2, _ := OpenStore(filepath.Join(dir, "visitors"), 365*24*time.Hour)
	r2 := &Reader{Glob: r.Glob, Suffix: r.Suffix, StateFile: r.StateFile, Store: st2}
	r2.Poll()
	rep = st2.Report(now.Add(-time.Hour), now.Add(time.Minute), "shop.example.ru")
	if rep.Total.Requests != 9 || rep.Total.Search["Google"] != 1 {
		t.Fatalf("after restart: %+v", rep.Total.Requests)
	}
	if st2.Report(now.Add(-time.Hour), now.Add(time.Minute), "other.example").Total.Requests != 0 {
		t.Fatal("site filter ignored")
	}
}

func TestCap(t *testing.T) {
	a := newAgg()
	for i := range maxKeys + 50 {
		count(a, "s", Request{Method: "GET", Path: fmt.Sprintf("/p%d", i), Status: 404, Agent: chrome})
	}
	if len(a.NotFound) != maxKeys+1 || a.NotFound[OtherKey] != 50 {
		t.Fatalf("%d keys, other %d", len(a.NotFound), a.NotFound[OtherKey])
	}
}

func TestExpire(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().AddDate(0, 0, -400).Format(time.DateOnly)
	os.WriteFile(filepath.Join(dir, old+".json.gz"), nil, 0o600)
	OpenStore(dir, 365*24*time.Hour)
	if _, err := os.Stat(filepath.Join(dir, old+".json.gz")); err == nil {
		t.Fatal("a day past the retention was kept")
	}
}
