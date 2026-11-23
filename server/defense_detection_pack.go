package server

import (
	"net/http"

	"github.com/Autumn-27/artex/detectionpack"
)

// Detection rules are read-only package data. These endpoints neither deploy
// sensor rules nor enable autonomous containment or response actions.
func (s *Server) defenseDetectionCatalog(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	if err := detectionpack.Validate(); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "detection pack validation failed")
		return
	}
	catalog, err := detectionpack.Catalog()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "detection pack unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"catalog": catalog,
		"installation": "operator-managed sensors only",
		"automatic_activation": false,
		"autonomous_containment": false,
		"downloads": map[string]string{
			"suricata": "/api/defense/detection-pack/suricata",
			"yara": "/api/defense/detection-pack/yara",
		},
	})
}

// GET /api/defense/detection-pack/{engine}: authenticated file retrieval.
// Neither engine name nor filename can refer to a user-controlled FS path.
func (s *Server) defenseDetectionDownload(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	if err := detectionpack.Validate(); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "detection pack validation failed")
		return
	}
	engine := r.PathValue("engine")
	var filename string
	switch engine {
	case "suricata":
		filename = "artex-alert-only.rules"
	case "yara":
		filename = "artex-alert-only.yar"
	default:
		writeErr(w, http.StatusNotFound, "unknown detection engine")
		return
	}
	content, err := detectionpack.Rules(engine)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "detection rule download unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}
