package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/defense"
)

type collectorIdentity struct {
	ID     int64
	Source string
}
type collectorContextKey struct{}

var collectorNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`)
var errCollectorCredential = errors.New("invalid collector credential")
var errCollectorStore = errors.New("collector credential store unavailable")

func collectorFromContext(ctx context.Context) *collectorIdentity {
	v, _ := ctx.Value(collectorContextKey{}).(*collectorIdentity)
	return v
}

// A collector credential is NOT an ARTEX admin JWT. It only authorizes
// POST /api/defense/collector/events. Do not accept cookies or URL tokens.
func (s *Server) collectorAuth(w http.ResponseWriter, r *http.Request, h http.Handler) {
	if !defense.Restricted() {
		writeErr(w, http.StatusNotFound, "collector ingestion requires defense mode")
		return
	}
	identity, err := s.authenticateCollector(r.Context(), r.Header.Get("Authorization"))
	if err != nil {
		if errors.Is(err, errCollectorStore) {
			writeErr(w, http.StatusServiceUnavailable, "collector authentication unavailable")
		} else {
			writeErr(w, http.StatusUnauthorized, "invalid collector credential")
		}
		return
	}
	h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), collectorContextKey{}, identity)))
}

// Tokens have an indexable, non-secret id and a 32-byte unpredictable secret.
// Their full SHA-256 digest is the only stored verifier. A leaked DB snapshot
// cannot recover the secret from its digest by practical brute force.
func newCollectorToken(id int64) (string, string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}
	token := fmt.Sprintf("dc1.%d.%s", id, base64.RawURLEncoding.EncodeToString(secret))
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

func collectorIDFromToken(raw string) (int64, bool) {
	if len(raw) > 160 || !strings.HasPrefix(raw, "Collector ") {
		return 0, false
	}
	parts := strings.Split(strings.TrimPrefix(raw, "Collector "), ".")
	if len(parts) != 3 || parts[0] != "dc1" {
		return 0, false
	}
	id, err := strconv.ParseInt(parts[1], 10, 64)
	secret, decodeErr := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || id <= 0 || decodeErr != nil || len(secret) != 32 {
		return 0, false
	}
	return id, true
}

func (s *Server) authenticateCollector(ctx context.Context, header string) (*collectorIdentity, error) {
	id, valid := collectorIDFromToken(header)
	if !valid {
		return nil, errCollectorCredential
	}
	if s.m == nil || s.m.pg == nil {
		return nil, errCollectorStore
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var source, hash string
	err := s.m.pg.QueryRowContext(ctx,
		`SELECT source,token_hash FROM defense_collectors WHERE id=$1 AND revoked_at IS NULL`, id).
		Scan(&source, &hash)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return nil, errCollectorStore
	}
	if err != nil {
		// A revoked/missing id and a bad hash have the same outward response.
		// Store outages return 503 rather than masquerading as revocation.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errCollectorCredential
		}
		return nil, errCollectorStore
	}
	sum := sha256.Sum256([]byte(strings.TrimPrefix(header, "Collector ")))
	got := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(hash)) != 1 {
		return nil, errCollectorCredential
	}
	return &collectorIdentity{ID: id, Source: source}, nil
}

// Called within the event ingestion transaction. This shared SQL minute
// bucket is atomic across processes, so spreading connections over workers
// cannot bypass the 600-events/minute cap. Rejected batches roll back.
func (s *Server) reserveCollectorBudget(ctx context.Context, tx *sql.Tx, id int64, count int) (bool, error) {
	var total int
	err := tx.QueryRowContext(ctx, `
        INSERT INTO defense_collector_rate(collector_id,minute_start,event_count)
        VALUES($1,date_trunc('minute',now()),$2)
        ON CONFLICT (collector_id,minute_start)
        DO UPDATE SET event_count=defense_collector_rate.event_count+EXCLUDED.event_count
        WHERE defense_collector_rate.event_count+EXCLUDED.event_count <= 600
        RETURNING event_count`, id, count).Scan(&total)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *Server) collectorCreate(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var input struct {
		Name   string `json:"name"`
		Source string `json:"source"`
	}
	if !decodeDefenseWorkflow(w, r, &input) {
		return
	}
	if !collectorNamePattern.MatchString(input.Name) {
		writeErr(w, 400, "name must be 3..64 ASCII letters/digits/dots/dashes/underscores")
		return
	}
	switch input.Source {
	case "suricata", "wazuh", "generic", "ocsf":
	default:
		writeErr(w, 400, "unsupported collector source")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "collector store unavailable")
		return
	}
	defer tx.Rollback()
	var id int64
	// Unique name conflicts are intentionally reported without leaking DB details.
	if err := tx.QueryRowContext(ctx, `INSERT INTO defense_collectors(name,source,token_hash)
        VALUES($1,$2,$3) ON CONFLICT(name) DO NOTHING RETURNING id`, input.Name, input.Source, strings.Repeat("0", 64)).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 409, "collector name already exists")
			return
		}
		writeErr(w, 503, "collector could not be created")
		return
	}
	token, hash, err := newCollectorToken(id)
	if err != nil {
		writeErr(w, 503, "collector token generation failed")
		return
	}
	if _, err = tx.ExecContext(ctx, `UPDATE defense_collectors SET token_hash=$1 WHERE id=$2`, hash, id); err != nil {
		writeErr(w, 503, "collector token could not be saved")
		return
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO defense_collector_audit(collector_id,operation,actor)
        VALUES($1,'created',$2)`, id, s.approver(r)); err != nil {
		writeErr(w, 503, "collector audit unavailable")
		return
	}
	if err = tx.Commit(); err != nil {
		writeErr(w, 503, "collector commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, map[string]any{"id": id, "name": input.Name, "source": input.Source, "token": token,
		"note": "Save this secret in a restricted credential store. It cannot be read again."})
}
func (s *Server) collectorList(w http.ResponseWriter, r *http.Request) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	rows, err := pg.QueryContext(ctx, `SELECT id,name,source,created_at,rotated_at,revoked_at
        FROM defense_collectors ORDER BY id DESC LIMIT 200`)
	if err != nil {
		writeErr(w, 503, "collector list unavailable")
		return
	}
	defer rows.Close()
	type item struct {
		ID      int64      `json:"id"`
		Name    string     `json:"name"`
		Source  string     `json:"source"`
		Created time.Time  `json:"created_at"`
		Rotated *time.Time `json:"rotated_at"`
		Revoked *time.Time `json:"revoked_at"`
	}
	out := make([]item, 0)
	for rows.Next() {
		var c item
		if err := rows.Scan(&c.ID, &c.Name, &c.Source, &c.Created, &c.Rotated, &c.Revoked); err != nil {
			writeErr(w, 503, "collector list unavailable")
			return
		}
		out = append(out, c)
	}
	if rows.Err() != nil {
		writeErr(w, 503, "collector list unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"collectors": out})
}
func (s *Server) collectorRotateOrRevoke(w http.ResponseWriter, r *http.Request, rotate bool) {
	if !s.defenseMode(w) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := workflowID(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := pg.BeginTx(ctx, nil)
	if err != nil {
		writeErr(w, 503, "collector store unavailable")
		return
	}
	defer tx.Rollback()
	var token string
	var res sql.Result
	if rotate {
		var hash string
		token, hash, err = newCollectorToken(id)
		if err == nil {
			res, err = tx.ExecContext(ctx, `UPDATE defense_collectors
            SET token_hash=$1,rotated_at=now()
            WHERE id=$2 AND revoked_at IS NULL`, hash, id)
		}
	} else {
		res, err = tx.ExecContext(ctx, `UPDATE defense_collectors
            SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	}
	if err != nil {
		writeErr(w, 503, "collector update failed")
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		writeErr(w, 503, "collector update failed")
		return
	}
	if n != 1 {
		writeErr(w, 404, "active collector not found")
		return
	}
	action := "revoked"
	if rotate {
		action = "rotated"
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO defense_collector_audit(collector_id,operation,actor)
        VALUES($1,$2,$3)`, id, action, s.approver(r)); err != nil {
		writeErr(w, 503, "collector audit unavailable")
		return
	}
	if err = tx.Commit(); err != nil {
		writeErr(w, 503, "collector commit failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if rotate {
		writeJSON(w, 200, map[string]any{"id": id, "token": token,
			"note": "Previous token immediately invalid; store this new token securely."})
	} else {
		writeJSON(w, 200, map[string]any{"id": id, "revoked": true})
	}
}
func (s *Server) collectorRotate(w http.ResponseWriter, r *http.Request) {
	s.collectorRotateOrRevoke(w, r, true)
}
func (s *Server) collectorRevoke(w http.ResponseWriter, r *http.Request) {
	s.collectorRotateOrRevoke(w, r, false)
}
