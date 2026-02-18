package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps a SQLite connection for the audit data store.
type DB struct {
	conn *sql.DB
	path string
}

// Open creates or opens a SQLite database at the given path.
func Open(path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	conn, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db := &DB{conn: conn, path: path}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate db: %w", err)
	}
	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// Conn returns the underlying sql.DB for direct queries.
func (db *DB) Conn() *sql.DB {
	return db.conn
}

func (db *DB) migrate() error {
	_, err := db.conn.Exec(schema)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    languages TEXT NOT NULL,  -- JSON array
    mode TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT 'init',
    round INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'running',
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    name TEXT NOT NULL,
    full_name TEXT,
    signature TEXT,
    file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    is_public BOOLEAN DEFAULT 0,
    annotation TEXT,
    complexity INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_functions_file ON functions(session_id, file_path);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(session_id, name);

CREATE TABLE IF NOT EXISTS call_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    caller_id INTEGER REFERENCES functions(id),
    callee_id INTEGER REFERENCES functions(id),
    call_site_line INTEGER,
    call_site_file TEXT
);

CREATE INDEX IF NOT EXISTS idx_call_edges_caller ON call_edges(caller_id);
CREATE INDEX IF NOT EXISTS idx_call_edges_callee ON call_edges(callee_id);

CREATE TABLE IF NOT EXISTS taint_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    source_func_id INTEGER REFERENCES functions(id),
    source_line INTEGER,
    source_expr TEXT,
    sink_func_id INTEGER REFERENCES functions(id),
    sink_line INTEGER,
    sink_expr TEXT,
    path_json TEXT,   -- JSON array of {file, line, expr, transform}
    rule_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_taint_flows_rule ON taint_flows(session_id, rule_id);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    message TEXT,
    cpg_evidence_json TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    confidence REAL DEFAULT 0.0,
    llm_verdict_json TEXT,
    fuzz_result_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_candidates_session ON candidates(session_id, status);
CREATE INDEX IF NOT EXISTS idx_candidates_rule ON candidates(session_id, rule_id);

CREATE TABLE IF NOT EXISTS evidence_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    candidate_id INTEGER REFERENCES candidates(id),
    discovery_json TEXT,
    cpg_evidence_json TEXT,
    llm_verification_json TEXT,
    fuzz_verification_json TEXT,
    final_status TEXT,
    final_severity TEXT,
    cwe TEXT,
    cvss REAL DEFAULT 0.0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    round INTEGER NOT NULL,
    dimension_id TEXT NOT NULL,
    dimension_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'uncovered',
    joern_rules BOOLEAN DEFAULT 0,
    llm_explored BOOLEAN DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    UNIQUE(session_id, round, dimension_id)
);
`
