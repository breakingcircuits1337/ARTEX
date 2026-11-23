package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestCollectorTokenFormat(t *testing.T) {
	token, hash, err := newCollectorToken(7)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := collectorIDFromToken("Collector " + token); !ok || id != 7 {
		t.Fatalf("token parse id=%d ok=%t", id, ok)
	}
	if _, ok := collectorIDFromToken("Bearer " + token); ok {
		t.Fatal("collector token accepted as JWT")
	}
	if _, ok := collectorIDFromToken("Collector dc1.7.test"); ok {
		t.Fatal("short secret accepted")
	}
	sum := sha256.Sum256([]byte(token))
	if got := hex.EncodeToString(sum[:]); got != hash {
		t.Fatal("token stored hash does not match")
	}
	if strings.Contains(hash, token) {
		t.Fatal("stored hash exposes secret")
	}
}

func TestCollectorAuthIsPathConfined(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	s := &Server{jwtKey: []byte(strings.Repeat("x", 32))}
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, path := range []string{"/api/defense/collectors", "/api/defense/emergency/arm"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Collector dc1.1.fake")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s accepted collector as an admin: HTTP %d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/defense/collector/events", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("dedicated endpoint accepted bad bearer: HTTP %d", rec.Code)
	}
}

func TestCollectorProvisionScopeReplayRotationAndRevokePG(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()
	s := &Server{m: m, jwtKey: []byte(strings.Repeat("k", 32))}
	admin, err := signJWTVersion(s.jwtKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/defense/collectors":
			s.collectorCreate(w, r)
		case "/api/defense/collector/events":
			s.ingestDefenseEvents(w, r)
		default:
			if strings.HasSuffix(r.URL.Path, "/rotate") {
				s.collectorRotate(w, r)
			} else {
				s.collectorRevoke(w, r)
			}
		}
	}))
	invoke := func(path, credential, body string, id int64) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if credential != "" {
			req.Header.Set("Authorization", credential)
		}
		if id > 0 {
			req.SetPathValue("id", strconv.FormatInt(id, 10))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	name := fmt.Sprintf("pr10-%d", time.Now().UnixNano())
	create := invoke("/api/defense/collectors", "Bearer "+admin,
		fmt.Sprintf(`{"name":"%s","source":"generic"}`, name), 0)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var c struct {
		ID    int64  `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if c.ID == 0 || !strings.HasPrefix(c.Token, "dc1.") {
		t.Fatal("missing token")
	}
	var hash string
	if err := m.pg.QueryRow(`SELECT token_hash FROM defense_collectors WHERE id=$1`, c.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == c.Token || strings.Contains(hash, "dc1.") {
		t.Fatal("credential stored in plaintext")
	}
	batch := `{"source":"generic","events":[{"event_id":"same-collector-test","kind":"other"}]}`
	feed := func(token, input string) *httptest.ResponseRecorder {
		return invoke("/api/defense/collector/events", "Collector "+token, input, 0)
	}
	a := feed(c.Token, batch)
	if a.Code != 200 {
		t.Fatalf("ingest status=%d body=%s", a.Code, a.Body.String())
	}
	b := feed(c.Token, batch)
	if b.Code != 200 || !bytes.Contains(b.Body.Bytes(), []byte(`"duplicates":1`)) {
		t.Fatalf("replay status=%d body=%s", b.Code, b.Body.String())
	}
	wrong := feed(c.Token, `{"source":"wazuh","events":[{"kind":"other"}]}`)
	if wrong.Code != 403 {
		t.Fatalf("cross-source post status=%d", wrong.Code)
	}
	var count int
	if err := m.pg.QueryRow(`SELECT count(*) FROM defense_events WHERE collector_id=$1`, c.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("source evidence count=%d error=%v", count, err)
	}
	second := invoke("/api/defense/collectors", "Bearer "+admin,
		fmt.Sprintf(`{"name":"%s-b","source":"generic"}`, name), 0)
	if second.Code != http.StatusCreated {
		t.Fatalf("second collector status=%d body=%s", second.Code, second.Body.String())
	}
	var c2 struct { ID int64 `json:"id"`; Token string `json:"token"` }
	if err := json.Unmarshal(second.Body.Bytes(), &c2); err != nil { t.Fatal(err) }
	if response := feed(c2.Token, batch); response.Code != 200 {
		t.Fatalf("same external ID from another sensor rejected: %d", response.Code)
	}
	if err := m.pg.QueryRow(`SELECT count(*) FROM defense_events WHERE external_id=$1 AND collector_id IN ($2,$3)`,
		"same-collector-test", c.ID, c2.ID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("per-collector provenance failed count=%d error=%v", count, err)
	}
	identity, err := s.authenticateCollector(context.Background(), "Collector "+c.Token)
	if err != nil { t.Fatal(err) }
	rotate := invoke(fmt.Sprintf("/api/defense/collectors/%d/rotate", c.ID), "Bearer "+admin, "", c.ID)
	if rotate.Code != 200 {
		t.Fatalf("rotate status=%d body=%s", rotate.Code, rotate.Body.String())
	}
	var replacement struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rotate.Body.Bytes(), &replacement); err != nil {
		t.Fatal(err)
	}
	if replacement.Token == "" || replacement.Token == c.Token {
		t.Fatal("rotation did not replace secret")
	}
	tx, err := m.pg.BeginTx(context.Background(), nil)
	if err != nil { t.Fatal(err) }
	valid, err := validateCollectorTransaction(context.Background(), tx, identity)
	_ = tx.Rollback()
	if err != nil || valid {
		t.Fatalf("stale in-flight identity survived rotation: valid=%v err=%v", valid, err)
	}
	if response := feed(c.Token, batch); response.Code != 401 {
		t.Fatalf("old credential allowed after rotation: %d", response.Code)
	}
	if response := feed(replacement.Token, batch); response.Code != 200 {
		t.Fatalf("new token rejected: %d", response.Code)
	}
	revoke := invoke(fmt.Sprintf("/api/defense/collectors/%d/revoke", c.ID), "Bearer "+admin, "", c.ID)
	if revoke.Code != 200 {
		t.Fatalf("revoke status=%d body=%s", revoke.Code, revoke.Body.String())
	}
	if response := feed(replacement.Token, batch); response.Code != 401 {
		t.Fatalf("revoked token accepted: %d", response.Code)
	}
}

func TestCollectorRateBudgetPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := m.pg.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	name := fmt.Sprintf("quota-%d", time.Now().UnixNano())
	var id int64
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO defense_collectors(name,source,token_hash) VALUES($1,'generic',$2) RETURNING id`,
		name, strings.Repeat("a", 64)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	ok, err := s.reserveCollectorBudget(ctx, tx, id, 599)
	if err != nil || !ok {
		t.Fatalf("reserve 599: %v ok=%v", err, ok)
	}
	ok, err = s.reserveCollectorBudget(ctx, tx, id, 2)
	if err != nil || ok {
		t.Fatalf("over budget: %v ok=%v", err, ok)
	}
	ok, err = s.reserveCollectorBudget(ctx, tx, id, 1)
	if err != nil || !ok {
		t.Fatalf("reserve final event: %v ok=%v", err, ok)
	}
}
