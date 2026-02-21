package orchestrator

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/joern-audit/joern_audit/internal/db"
)

// SaveSession persists a session to the SQLite database.
func SaveSession(database *db.DB, session *Session) error {
	langsJSON, _ := json.Marshal(session.Languages)

	_, err := database.Conn().Exec(`
		INSERT INTO sessions (id, target, languages, mode, phase, round, status, started_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			phase = excluded.phase,
			round = excluded.round,
			status = excluded.status,
			updated_at = excluded.updated_at
	`,
		session.ID,
		session.Target,
		string(langsJSON),
		session.Mode,
		session.Phase.String(),
		session.Round,
		session.Status,
		session.StartedAt.Format(time.RFC3339),
		session.UpdatedAt.Format(time.RFC3339),
	)
	return err
}

// LoadSession reads a session from the SQLite database by ID.
func LoadSession(database *db.DB, sessionID string) (*Session, error) {
	row := database.Conn().QueryRow(`
		SELECT id, target, languages, mode, phase, round, status, started_at, updated_at
		FROM sessions WHERE id = ?
	`, sessionID)

	var (
		id, target, langsStr, mode, phaseStr, status string
		round                                        int
		startedAt, updatedAt                         string
	)

	err := row.Scan(&id, &target, &langsStr, &mode, &phaseStr, &round, &status, &startedAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session %s not found", sessionID)
		}
		return nil, fmt.Errorf("scan session: %w", err)
	}

	var languages []string
	json.Unmarshal([]byte(langsStr), &languages)

	parsedStart, _ := time.Parse(time.RFC3339, startedAt)
	parsedUpdate, _ := time.Parse(time.RFC3339, updatedAt)

	return &Session{
		ID:        id,
		Target:    target,
		Languages: languages,
		Mode:      mode,
		Phase:     parsePhase(phaseStr),
		Round:     round,
		Status:    status,
		StartedAt: parsedStart,
		UpdatedAt: parsedUpdate,
	}, nil
}

// ListSessions returns all sessions from the database, most recent first.
func ListSessions(database *db.DB) ([]*Session, error) {
	rows, err := database.Conn().Query(`
		SELECT id, target, languages, mode, phase, round, status, started_at, updated_at
		FROM sessions ORDER BY started_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		var (
			id, target, langsStr, mode, phaseStr, status string
			round                                        int
			startedAt, updatedAt                         string
		)
		if err := rows.Scan(&id, &target, &langsStr, &mode, &phaseStr, &round, &status, &startedAt, &updatedAt); err != nil {
			return nil, err
		}

		var languages []string
		json.Unmarshal([]byte(langsStr), &languages)
		parsedStart, _ := time.Parse(time.RFC3339, startedAt)
		parsedUpdate, _ := time.Parse(time.RFC3339, updatedAt)

		sessions = append(sessions, &Session{
			ID:        id,
			Target:    target,
			Languages: languages,
			Mode:      mode,
			Phase:     parsePhase(phaseStr),
			Round:     round,
			Status:    status,
			StartedAt: parsedStart,
			UpdatedAt: parsedUpdate,
		})
	}
	return sessions, rows.Err()
}

func parsePhase(s string) Phase {
	mapping := map[string]Phase{
		"init":         PhaseInit,
		"cpg_build":    PhaseCPGBuild,
		"llm_verify":   PhaseLLMVerify,
		"fuzz_verify":  PhaseFuzzVerify,
		"attack_chain": PhaseAttackChain,
		"report":       PhaseReport,
	}
	if p, ok := mapping[s]; ok {
		return p
	}
	return PhaseInit
}
