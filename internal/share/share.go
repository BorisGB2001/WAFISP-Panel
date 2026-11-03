// Package share exchanges blocks between the panels of several servers.
// Every panel publishes the blocks it made itself (by hand, auto-ban,
// traps, mass bans), signed with its own key, and applies the lists of the
// peers it trusts. What travels is the whole list, not events: a block
// added, extended or lifted on one server follows on the others at the
// next pull, and a panel that was down catches up by itself.
//
// Each server keeps the last word on its own addresses: its protected
// list, Cloudflare and its allow list are never blocked, and a peer's
// block unblocked here by hand stays unblocked.
package share

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// Item is one block in a server's list.
type Item struct {
	IP      string    `json:"ip"`
	At      time.Time `json:"at"`
	Expires time.Time `json:"expires,omitzero"`
	Reason  string    `json:"reason,omitempty"`
	By      string    `json:"by,omitempty"`
	Via     string    `json:"via,omitempty"`
	Site    string    `json:"site,omitempty"`
}

// List is what one server publishes.
type List struct {
	Server string    `json:"server"`
	At     time.Time `json:"at"`
	Items  []Item    `json:"items"`
}

// envelope is the file in the store: the list exactly as signed, and the
// signature.
type envelope struct {
	List json.RawMessage `json:"list"`
	Sig  []byte          `json:"sig"`
}

// MaxItems bounds a list, so one server cannot flood the others.
const MaxItems = 20000

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidName tells a server name: lowercase letters, digits, - and _.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// Seal signs l.
func Seal(priv ed25519.PrivateKey, l List) ([]byte, error) {
	body, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{List: body, Sig: ed25519.Sign(priv, body)})
}

// Unseal checks the signature of a file of server name and returns its list.
func Unseal(data []byte, name string, pub ed25519.PublicKey) (List, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return List{}, fmt.Errorf("not a block list: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, env.List, env.Sig) {
		return List{}, errors.New("bad signature: not signed by this server's key")
	}
	var l List
	dec := json.NewDecoder(bytes.NewReader(env.List))
	if err := dec.Decode(&l); err != nil {
		return List{}, err
	}
	if l.Server != name {
		return List{}, fmt.Errorf("the list says it is from %q", l.Server)
	}
	if len(l.Items) > MaxItems {
		return List{}, fmt.Errorf("%d blocks, more than %d", len(l.Items), MaxItems)
	}
	return l, nil
}

// ErrNotFound is a list nobody published yet.
var ErrNotFound = errors.New("not published yet")

// Store keeps the lists, one file per server.
type Store interface {
	Get(ctx context.Context, server string) ([]byte, error)
	Put(ctx context.Context, server string, data []byte) error
}

// same tells whether two lists hold the same blocks.
func same(a, b []Item) bool {
	return slices.EqualFunc(a, b, func(x, y Item) bool {
		return x.IP == y.IP && x.At.Equal(y.At) && x.Expires.Equal(y.Expires) && x.Reason == y.Reason
	})
}
