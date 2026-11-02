// Package i18n translates the panel. English is the source language and
// the default: every message is written in English and used as the key of
// the Russian catalog. A missing translation falls back to English.
package i18n

import (
	"errors"
	"fmt"
)

const (
	EN = "en"
	RU = "ru"
)

// Langs are the languages offered in the UI, default first.
var Langs = []string{EN, RU}

func Valid(lang string) bool { return lang == EN || lang == RU }

// T translates s and formats it with args like fmt.Sprintf.
func T(lang, s string, args ...any) string {
	if lang == RU {
		if t, ok := ru[s]; ok {
			s = t
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// Has reports whether s has a Russian translation (used by tests).
func Has(s string) bool { _, ok := ru[s]; return ok }

// Msg is an error whose text is translated when it is shown, so code deep
// in the stack does not need to know the reader's language.
type Msg struct {
	Key  string
	Args []any
}

func (m *Msg) Error() string { return T(EN, m.Key, m.Args...) }

// Errorf returns a translatable error.
func Errorf(key string, args ...any) error { return &Msg{Key: key, Args: args} }

// Text renders err in lang; plain errors (from nginx, mgrctl, the network)
// stay as they are.
func Text(lang string, err error) string {
	if err == nil {
		return ""
	}
	var m *Msg
	if errors.As(err, &m) {
		return T(lang, m.Key, m.Args...)
	}
	return err.Error()
}
