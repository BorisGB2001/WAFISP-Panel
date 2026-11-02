package web

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"wafisp/internal/auth"
)

type ctxKey struct{}

// reqCtx is what every page knows about the signed-in user.
type reqCtx struct {
	User auth.User
	CSRF string
}

type handler func(w http.ResponseWriter, r *http.Request, rc *reqCtx)

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; style-src-attr 'unsafe-inline'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// authed checks the session, the CSRF token of POST requests and, when
// admin is set, the role.
func (s *Server) authed(h handler, admin bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		var rc *reqCtx
		if err == nil {
			if sess, ok := s.sessions.Parse(c.Value); ok {
				if u, ok := s.users.Get(sess.User); ok && u.Version == sess.Version {
					rc = &reqCtx{User: u, CSRF: s.sessions.CSRF(sess)}
				}
			}
		}
		if rc == nil {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			} else {
				http.Error(w, tr(r, "Sign-in required"), http.StatusUnauthorized)
			}
			return
		}
		if r.Method == http.MethodPost {
			if !sameOrigin(r) || r.FormValue("csrf") != rc.CSRF {
				http.Error(w, tr(r, "CSRF check failed, reload the page"), http.StatusForbidden)
				return
			}
		}
		if admin && rc.User.Role != auth.RoleAdmin {
			http.Error(w, tr(r, "Administrator role required"), http.StatusForbidden)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, rc)), rc)
	})
}

// sameOrigin rejects cross-site posts as a second line after SameSite and CSRF.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

func (s *Server) setSession(w http.ResponseWriter, u auth.User) {
	v, _ := s.sessions.New(u)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: v, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.sessions.TTL() / time.Second),
	})
}

func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
