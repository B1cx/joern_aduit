package evidence

import (
	"fmt"
	"sync"
)

// MemoryStore is an in-memory implementation of the Store interface for MVP.
// Production version should use SQLite.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]*Record // candidateID -> Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records: make(map[string]*Record),
	}
}

func (s *MemoryStore) Save(record *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.CandidateID] = record
	return nil
}

func (s *MemoryStore) Get(candidateID string) (*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[candidateID]
	if !ok {
		return nil, fmt.Errorf("record not found: %s", candidateID)
	}
	return rec, nil
}

func (s *MemoryStore) List(sessionID string) ([]*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var results []*Record
	for _, rec := range s.records {
		results = append(results, rec)
	}
	return results, nil
}

func (s *MemoryStore) UpdateStatus(candidateID string, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[candidateID]
	if !ok {
		return fmt.Errorf("record not found: %s", candidateID)
	}
	rec.FinalSeverity = status
	return nil
}
