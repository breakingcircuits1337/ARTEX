package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/defense"
)

// Incident correlation is intentionally out of the emergency containment
// path. It operates only on already-ingested rows and cannot call an agent,
// a scanner, DNS, shell, nftables or an external response connector.
const (
	caseCorrelationLimit  = 50
	caseCorrelationWindow = 15 * time.Minute
)

type correlatedEvent struct {
	ID          int64
	Source      string
	CollectorID sql.NullInt64
	Kind        string
	SrcIP       string
	DstIP       string
	Host        string
	Signature   string
	ObservedAt  time.Time
	Reason      string
	Confidence  int
}

type correlationCounts struct {
	Observations int `json:"observations"`
	Indicators   int `json:"indicators"`
	Relations    int `json:"relations"`
}

// correlateDefenseCase is called in an existing transaction while the case
// is locked. All evidence and graph edges commit or roll back together.
// An evidence ID is always an existing defense_events row.
func correlateDefenseCase(ctx context.Context, tx *sql.Tx, caseID int64, actor string) (correlationCounts, error) {
	var result correlationCounts
	var anchor correlatedEvent
	var ruleID string
	err := tx.QueryRowContext(ctx, `
		SELECT e.id,e.source,e.kind,e.src_ip,e.dst_ip,e.host,
		       e.signature,e.observed_at,a.rule_id,e.collector_id
		  FROM defense_cases c
		  JOIN defense_alerts a ON a.id=c.alert_id
		  JOIN defense_events e ON e.id=a.event_id
		 WHERE c.id=$1 FOR SHARE OF c`, caseID).Scan(
		&anchor.ID, &anchor.Source, &anchor.Kind, &anchor.SrcIP,
		&anchor.DstIP, &anchor.Host, &anchor.Signature,
		&anchor.ObservedAt, &ruleID, &anchor.CollectorID,
	)
	if err != nil {
		return result, err
	}
	// Same collector identity (or legacy NULL) + vendor, two matching fields,
	// and a 30-minute window. Cross-collector links need a separately
	// validated multi-sensor correlation policy (not in this phase).
	// Matching an IP alone (NAT/shared gateways) is not sufficient to connect
	// events. All of these links remain unconfirmed investigative candidates.
	rows, err := tx.QueryContext(ctx, `
		SELECT e.id,e.source,e.kind,e.src_ip,e.dst_ip,e.host,
		       e.signature,e.observed_at
		  FROM defense_events e
		 WHERE e.id=$1 OR (
		     e.source=$2
		     AND e.collector_id IS NOT DISTINCT FROM $9::bigint
		     AND e.observed_at BETWEEN $6 AND $7
		     AND (
		       ($3<>'' AND $4<>'' AND e.src_ip=$3 AND e.dst_ip=$4)
		       OR ($3<>'' AND $5<>'' AND e.src_ip=$3 AND e.host=$5)
		     )
		 )
		 ORDER BY CASE WHEN e.id=$1 THEN 0 ELSE 1 END,
		          e.observed_at DESC,e.id DESC
		 LIMIT $8`,
		anchor.ID, anchor.Source, anchor.SrcIP, anchor.DstIP, anchor.Host,
		anchor.ObservedAt.Add(-caseCorrelationWindow),
		anchor.ObservedAt.Add(caseCorrelationWindow),
		caseCorrelationLimit, anchor.CollectorID)
	if err != nil {
		return result, err
	}
	var candidates []correlatedEvent
	for rows.Next() {
		var e correlatedEvent
		if err := rows.Scan(&e.ID, &e.Source, &e.Kind, &e.SrcIP,
			&e.DstIP, &e.Host, &e.Signature, &e.ObservedAt); err != nil {
			rows.Close()
			return result, err
		}
		if e.ID == anchor.ID {
			e.Reason, e.Confidence = "alert_anchor", 95
		} else if anchor.SrcIP != "" && anchor.DstIP != "" &&
			e.SrcIP == anchor.SrcIP && e.DstIP == anchor.DstIP {
			e.Reason, e.Confidence = "same_source_and_endpoints", 55
		} else {
			e.Reason, e.Confidence = "same_source_and_host_ip", 50
		}
		candidates = append(candidates, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return result, err
	}
	rows.Close()
	if len(candidates) == 0 {
		return result, errors.New("case alert anchor missing from telemetry")
	}

	for _, e := range candidates {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO defense_case_observations(case_id,event_id,link_reason,linkage_confidence)
			VALUES($1,$2,$3,$4)
			ON CONFLICT(case_id,event_id) DO NOTHING`,
			caseID, e.ID, e.Reason, e.Confidence); err != nil {
			return result, err
		}
		result.Observations++
		indicators := defense.CaseIndicators(e.SrcIP, e.DstIP, e.Host, e.Signature)
		var sourceID, targetID int64
		for _, i := range indicators {
			var indicatorID int64
			err := tx.QueryRowContext(ctx, `
				INSERT INTO defense_case_indicators
				 (case_id,indicator_type,indicator_value,confidence,
				  first_seen,last_seen,first_event_id)
				VALUES($1,$2,$3,$4,$5,$5,$6)
				ON CONFLICT(case_id,indicator_type,indicator_value)
				DO UPDATE SET first_seen=LEAST(defense_case_indicators.first_seen,EXCLUDED.first_seen),
				              last_seen=GREATEST(defense_case_indicators.last_seen,EXCLUDED.last_seen),
				              confidence=GREATEST(defense_case_indicators.confidence,EXCLUDED.confidence)
				RETURNING id`,
				caseID, i.Type, i.Value, e.Confidence, e.ObservedAt, e.ID).Scan(&indicatorID)
			if err != nil {
				return result, err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO defense_indicator_evidence
				 (indicator_id,case_id,event_id,evidence_role,observed_at)
				VALUES($1,$2,$3,$4,$5)
				ON CONFLICT DO NOTHING`,
				indicatorID, caseID, e.ID, i.Role, e.ObservedAt); err != nil {
				return result, err
			}
			result.Indicators++
			if i.Role == "source_ip" {
				sourceID = indicatorID
			}
			if i.Role == "destination_ip" {
				targetID = indicatorID
			}
		}
		// Same-event IP co-observation is real provenance. The edge is NOT
		// traffic direction, attacker attribution or causal certainty.
		if sourceID > 0 && targetID > 0 && sourceID != targetID {
			left, right := sourceID, targetID
			if left > right {
				left, right = right, left
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO defense_case_relations
				 (case_id,source_indicator_id,target_indicator_id,evidence_event_id)
				VALUES($1,$2,$3,$4)
				ON CONFLICT DO NOTHING`, caseID, left, right, e.ID); err != nil {
				return result, err
			}
			result.Relations++
		}
	}
	// ATT&CK IDs here are hypotheses, not verified attacker behavior.
	// Imported signatures never produce automatic technique mappings.
	if technique, tactic, ok := defense.KnownRuleATTACKHint(ruleID); ok {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO defense_case_techniques
			 (case_id,technique_id,tactic_id,confidence,mapping_source,rationale,evidence_event_id)
			VALUES($1,$2,$3,35,'rule_hint',
			       'Low-confidence rule-category hint; analyst must confirm actual behavior with independent evidence.',
			       $4)
			ON CONFLICT DO NOTHING`, caseID, technique, tactic, anchor.ID); err != nil {
			return result, err
		}
	}
	if actor != "" {
		detail := fmt.Sprintf("Evidence-only correlation: %d events reviewed; up to %d candidates within ±15 minutes; no external actions",
			len(candidates), caseCorrelationLimit)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO defense_case_intel_audit(case_id,audit_kind,actor,detail)
			VALUES($1,'refreshed',$2,$3)`, caseID, actor, detail); err != nil {
			return result, err
		}
	}
	return result, nil
}
