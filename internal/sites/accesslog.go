package sites

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"slices"
)

// LogSwitch turns a site's request log on and off in ISPmanager, through
// mgrctl, the way the site's settings page does. ISPmanager then rewrites
// the vhost and reloads nginx itself; the panel never edits the vhost.
type LogSwitch struct {
	Mgrctl string // /usr/local/mgr5/sbin/mgrctl
	Sites  *Reader
	// Run runs a command; exec by default (tests replace it).
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (l *LogSwitch) run(ctx context.Context, args ...string) ([]byte, error) {
	if l.Run != nil {
		return l.Run(ctx, l.Mgrctl, args...)
	}
	return exec.CommandContext(ctx, l.Mgrctl, args...).CombinedOutput()
}

// Set turns the request log of site on or off. Only sites ISPmanager has
// a vhost for are accepted.
func (l *LogSwitch) Set(ctx context.Context, site string, on bool) error {
	if !slices.ContainsFunc(l.Sites.Sites(), func(s Site) bool { return s.Name == site }) {
		return fmt.Errorf("unknown site %q", site)
	}
	v := "off"
	if on {
		v = "on"
	}
	out, err := l.run(ctx, "-m", "ispmgr", "webdomain.edit", "elid="+site, "log_access="+v, "sok=ok")
	defer l.Sites.Forget()
	switch {
	case err != nil:
		return fmt.Errorf("mgrctl webdomain.edit %s: %v %s", site, err, bytes.TrimSpace(out))
	case bytes.Contains(out, []byte("Object: 'locked'")):
		return fmt.Errorf("ISPmanager is busy (locked), try again later")
	case bytes.Contains(out, []byte("ERROR")):
		return fmt.Errorf("mgrctl webdomain.edit %s: %s", site, bytes.TrimSpace(out))
	}
	return nil
}
