package evidence

// Store is the interface for persisting evidence records.
type Store interface {
	Save(record *Record) error
	Get(candidateID string) (*Record, error)
	List(sessionID string) ([]*Record, error)
	UpdateStatus(candidateID string, status string) error
}
