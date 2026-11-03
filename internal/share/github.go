package share

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// GitHub keeps the lists in a private repository, as blocks/<server>.json.
// The token needs read and write access to the contents of that one
// repository and nothing else. Unchanged files are answered 304 thanks to
// ETags, which do not count against the rate limit.
type GitHub struct {
	API    string // https://api.github.com by default
	Repo   string // owner/name
	Branch string
	Token  string
	HTTP   *http.Client

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	etag, sha string
	data      []byte
}

func (g *GitHub) url(server string) string {
	api := g.API
	if api == "" {
		api = "https://api.github.com"
	}
	return fmt.Sprintf("%s/repos/%s/contents/blocks/%s.json", api, g.Repo, server)
}

func (g *GitHub) do(ctx context.Context, method, url string, body io.Reader, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return g.HTTP.Do(req)
}

// Get returns the file of server.
func (g *GitHub) Get(ctx context.Context, server string) ([]byte, error) {
	g.mu.Lock()
	if g.cache == nil {
		g.cache = map[string]cached{}
	}
	c := g.cache[server]
	g.mu.Unlock()
	hdr := map[string]string{}
	if c.etag != "" {
		hdr["If-None-Match"] = c.etag
	}
	url := g.url(server)
	if g.Branch != "" {
		url += "?ref=" + g.Branch
	}
	resp, err := g.do(ctx, http.MethodGet, url, nil, hdr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return c.data, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusOK:
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GitHub: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var f struct {
		SHA      string `json:"sha"`
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&f); err != nil {
		return nil, fmt.Errorf("GitHub: %w", err)
	}
	if f.Encoding != "base64" {
		return nil, fmt.Errorf("GitHub: the file is too big to read through the API")
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("GitHub: %w", err)
	}
	g.mu.Lock()
	g.cache[server] = cached{etag: resp.Header.Get("ETag"), sha: f.SHA, data: data}
	g.mu.Unlock()
	return data, nil
}

// Put writes the file of server, creating it the first time.
func (g *GitHub) Put(ctx context.Context, server string, data []byte) error {
	for try := 0; try < 2; try++ {
		g.mu.Lock()
		sha := g.cache[server].sha
		g.mu.Unlock()
		if sha == "" || try > 0 {
			if _, err := g.Get(ctx, server); err != nil && err != ErrNotFound {
				return err
			}
			g.mu.Lock()
			sha = g.cache[server].sha
			g.mu.Unlock()
		}
		body := map[string]string{"message": "blocks of " + server, "content": base64.StdEncoding.EncodeToString(data)}
		if sha != "" {
			body["sha"] = sha
		}
		if g.Branch != "" {
			body["branch"] = g.Branch
		}
		b, _ := json.Marshal(body)
		resp, err := g.do(ctx, http.MethodPut, g.url(server), bytes.NewReader(b), map[string]string{"Content-Type": "application/json"})
		if err != nil {
			return err
		}
		var out struct {
			Content struct {
				SHA string `json:"sha"`
			} `json:"content"`
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
			json.Unmarshal(rb, &out)
			g.mu.Lock()
			if g.cache == nil {
				g.cache = map[string]cached{}
			}
			g.cache[server] = cached{sha: out.Content.SHA} // the next Get reads it again
			g.mu.Unlock()
			return nil
		case resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusUnprocessableEntity:
			continue // the file changed since we read it: read its sha again
		default:
			return fmt.Errorf("GitHub: %s: %s", resp.Status, strings.TrimSpace(string(rb[:min(len(rb), 512)])))
		}
	}
	return fmt.Errorf("GitHub: the file kept changing while writing it")
}
