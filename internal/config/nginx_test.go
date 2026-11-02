package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEmptyNginxCommands: empty test and reload lists stay empty, so a
// first deploy can write the panel's rules without touching nginx.
func TestEmptyNginxCommands(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "c.yaml"), []byte("nginx: {test: [], reload: []}"), 0o600)
	c, err := Load(filepath.Join(dir, "c.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Nginx.Test) != 0 || len(c.Nginx.Reload) != 0 {
		t.Fatalf("empty lists replaced by defaults: %v %v", c.Nginx.Test, c.Nginx.Reload)
	}
}
