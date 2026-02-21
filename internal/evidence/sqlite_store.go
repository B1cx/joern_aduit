package evidence

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/joern-audit/joern_audit/internal/cpg"
	"github.com/joern-audit/joern_audit/internal/db"
)

// SQLiteStore implements the Store interface backed by SQLite.
type SQLiteStore struct {
	db        *db.DB
	sessionID string
	mu        sync.Mutex
}

// NewSQLiteStore creates a new SQLite-backed evidence store.
func NewSQLiteStore(database *db.DB, sessionID string) *SQLiteStore {
	return &SQLiteStore{db: database, sessionID: sessionID}
}

func (s *SQLiteStore) Save(record *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cpgJSON, _ := json.Marshal(record.CPGEvidence)
	llmJSON, _ := json.Marshal(record.LLMVerify)
	fuzzJSON, _ := json.Marshal(record.FuzzVerify)

	_, err := s.db.Conn().Exec(`
		INSERT INTO evidence_records (
			session_id, candidate_id, rule_id, file_path, line_number,
			initial_severity, cpg_evidence_json,
			llm_verification_json, fuzz_verification_json,
			final_status, final_severity, cwe
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_id, candidate_id) DO UPDATE SET
			cpg_evidence_json = excluded.cpg_evidence_json,
			llm_verification_json = excluded.llm_verification_json,
			fuzz_verification_json = excluded.fuzz_verification_json,
			final_status = excluded.final_status,
			final_severity = excluded.final_severity,
			cwe = excluded.cwe
	`,
		s.sessionID,
		record.CandidateID,
		record.RuleID,
		record.FilePath,
		record.LineNumber,
		record.InitialSeverity,
		string(cpgJSON),
		string(llmJSON),
		string(fuzzJSON),
		statusFromRecord(record),
		record.FinalSeverity,
		record.CWE,
	)
	return err
}

func (s *SQLiteStore) Get(candidateID string) (*Record, error) {
	row := s.db.Conn().QueryRow(`
		SELECT candidate_id, rule_id, file_path, line_number,
		       initial_severity, cpg_evidence_json,
		       llm_verification_json, fuzz_verification_json,
		       final_severity, cwe
		FROM evidence_records
		WHERE session_id = ? AND candidate_id = ?
	`, s.sessionID, candidateID)

	return scanRecord(row)
}

func (s *SQLiteStore) List(sessionID string) ([]*Record, error) {
	sid := s.sessionID
	if sessionID != "" {
		sid = sessionID
	}

	rows, err := s.db.Conn().Query(`
		SELECT candidate_id, rule_id, file_path, line_number,
		       initial_severity, cpg_evidence_json,
		       llm_verification_json, fuzz_verification_json,
		       final_severity, cwe
		FROM evidence_records
		WHERE session_id = ?
		ORDER BY rowid
	`, sid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*Record
	for rows.Next() {
		rec, err := scanRecordRow(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	return results, rows.Err()
}

func (s *SQLiteStore) UpdateStatus(candidateID string, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Conn().Exec(`
		UPDATE evidence_records SET final_severity = ?
		WHERE session_id = ? AND candidate_id = ?
	`, status, s.sessionID, candidateID)
	return err
}

// --- helpers ---

func statusFromRecord(rec *Record) string {
	if rec.FuzzVerify != nil && rec.FuzzVerify.Result == "CONFIRMED" {
		return "fuzz_confirmed"
	}
	if rec.LLMVerify != nil && rec.LLMVerify.Judge != nil {
		return "llm_" + string(rec.LLMVerify.Judge.Verdict)
	}
	return "pending"
}

func scanRecord(row *sql.Row) (*Record, error) {
	var (
		candidateID, ruleID, filePath string
		lineNumber                    int
		initialSeverity               string
		cpgJSON, llmJSON, fuzzJSON    sql.NullString
		severity, cwe                 string
	)
	err := row.Scan(&candidateID, &ruleID, &filePath, &lineNumber,
		&initialSeverity, &cpgJSON, &llmJSON, &fuzzJSON, &severity, &cwe)
	if err != nil {
		return nil, fmt.Errorf("scan record: %w", err)
	}
	return deserializeRecord(candidateID, ruleID, filePath, lineNumber,
		initialSeverity, cpgJSON.String, llmJSON.String, fuzzJSON.String, severity, cwe)
}

func scanRecordRow(rows *sql.Rows) (*Record, error) {
	var (
		candidateID, ruleID, filePath string
		lineNumber                    int
		initialSeverity               string
		cpgJSON, llmJSON, fuzzJSON    sql.NullString
		severity, cwe                 string
	)
	err := rows.Scan(&candidateID, &ruleID, &filePath, &lineNumber,
		&initialSeverity, &cpgJSON, &llmJSON, &fuzzJSON, &severity, &cwe)
	if err != nil {
		return nil, fmt.Errorf("scan record row: %w", err)
	}
	return deserializeRecord(candidateID, ruleID, filePath, lineNumber,
		initialSeverity, cpgJSON.String, llmJSON.String, fuzzJSON.String, severity, cwe)
}

func deserializeRecord(candidateID, ruleID, filePath string, lineNumber int,
	initialSeverity, cpgJSON, llmJSON, fuzzJSON, severity, cwe string) (*Record, error) {

	rec := &Record{
		CandidateID:     candidateID,
		RuleID:          ruleID,
		FilePath:        filePath,
		LineNumber:      lineNumber,
		InitialSeverity: initialSeverity,
		FinalSeverity:   severity,
		CWE:             cwe,
	}

	if cpgJSON != "" && cpgJSON != "null" {
		var ev cpg.CPGEvidence
		if err := json.Unmarshal([]byte(cpgJSON), &ev); err == nil {
			rec.CPGEvidence = &ev
		}
	}
	if llmJSON != "" && llmJSON != "null" {
		var llm LLMVerification
		if err := json.Unmarshal([]byte(llmJSON), &llm); err == nil {
			rec.LLMVerify = &llm
		}
	}
	if fuzzJSON != "" && fuzzJSON != "null" {
		var fuzz FuzzVerification
		if err := json.Unmarshal([]byte(fuzzJSON), &fuzz); err == nil {
			rec.FuzzVerify = &fuzz
		}
	}
	return rec, nil
}
