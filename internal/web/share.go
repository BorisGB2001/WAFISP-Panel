package web

import (
	"net/http"

	"wafisp/internal/block"
)

// sharePage shows the exchange of blocks with other servers.
func (s *Server) sharePage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	data := map[string]any{"On": s.Share != nil}
	if s.Share != nil {
		self, peers := s.Share.Statuses()
		imported := map[string][]block.Entry{}
		for _, e := range s.Blocks.Entries() {
			if e.Peer != "" {
				imported[e.Peer] = append(imported[e.Peer], e)
			}
		}
		data["Self"], data["Peers"], data["Imported"] = self, peers, imported
		data["Own"] = len(s.Share.Own())
		data["Cfg"] = s.Cfg.Share
	}
	s.render(w, r, rc, "share.html", page{Title: "Shared blocks", Active: "share", Data: data})
}
