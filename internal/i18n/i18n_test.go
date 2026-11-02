package i18n

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// same are words that read the same in Russian.
var same = map[string]bool{"Rate limit": true, "Anti-Bot": true, "IP hash": true, "Deny": true, "Pass": true}

// TestCatalogCoversSources fails when a template or a translated call in Go
// uses a text that has no Russian translation.
func TestCatalogCoversSources(t *testing.T) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`\{\{-?\s*t\s+"((?:[^"\\]|\\.)*)"`),
		regexp.MustCompile(`\(t\s+"((?:[^"\\]|\\.)*)"`),
		regexp.MustCompile(`\btr\(r, "((?:[^"\\]|\\.)*)"`),
		regexp.MustCompile(`i18n\.Errorf\("((?:[^"\\]|\\.)*)"`),
		regexp.MustCompile(`\bt\("((?:[^"\\]|\\.)*)"`),
		regexp.MustCompile(`i18n\.T\(lang, "((?:[^"\\]|\\.)*)"`),
	}
	root := filepath.Join("..", "..")
	var files []string
	filepath.Walk(filepath.Join(root, "internal"), func(p string, info os.FileInfo, err error) error {
		if err == nil && (strings.HasSuffix(p, ".html") || (strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go"))) && !strings.Contains(p, "/i18n/") {
			files = append(files, p)
		}
		return nil
	})
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, re := range patterns {
			for _, m := range re.FindAllStringSubmatch(string(b), -1) {
				k := strings.ReplaceAll(m[1], `\"`, `"`)
				if k == "Site %s " || same[k] {
					continue
				}
				if !Has(k) {
					t.Errorf("%s: no Russian for %q", f, k)
				}
			}
		}
	}
}

func TestTranslate(t *testing.T) {
	if T(EN, "Blocked %s (%s)", "1.2.3.4", "1 hour") != "Blocked 1.2.3.4 (1 hour)" {
		t.Fatal("english")
	}
	if T(RU, "Blocked %s (%s)", "1.2.3.4", "1 час") != "Заблокирован 1.2.3.4 (1 час)" {
		t.Fatal("russian")
	}
	if Text(RU, Errorf("Port %d is listed twice", 80)) != "Порт 80 указан дважды" {
		t.Fatal("error text")
	}
	if T(RU, "no such key") != "no such key" {
		t.Fatal("fallback")
	}
}
