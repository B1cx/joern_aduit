package cpg

import (
	"fmt"
	"sync"
)

// MemoryIndexStore is an in-memory implementation of IndexStore for MVP.
// Production version should use SQLite.
type MemoryIndexStore struct {
	mu         sync.RWMutex
	functions  map[int64]*Function
	callEdges  []CallEdge
	taintFlows []TaintPath
	locIndex   map[string]*Function // file:line -> function
}

func NewMemoryIndexStore() *MemoryIndexStore {
	return &MemoryIndexStore{
		functions:  make(map[int64]*Function),
		callEdges:  make([]CallEdge, 0),
		taintFlows: make([]TaintPath, 0),
		locIndex:   make(map[string]*Function),
	}
}

func (s *MemoryIndexStore) SaveFunctions(funcs []Function) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range funcs {
		s.functions[funcs[i].ID] = &funcs[i]
		// Build location index
		for line := funcs[i].StartLine; line <= funcs[i].EndLine; line++ {
			key := fmt.Sprintf("%s:%d", funcs[i].FilePath, line)
			s.locIndex[key] = &funcs[i]
		}
	}
	return nil
}

func (s *MemoryIndexStore) SaveCallEdges(edges []CallEdge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callEdges = append(s.callEdges, edges...)
	return nil
}

func (s *MemoryIndexStore) SaveTaintFlows(flows []TaintPath) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.taintFlows = append(s.taintFlows, flows...)
	return nil
}

func (s *MemoryIndexStore) GetFunction(id int64) (*Function, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn, ok := s.functions[id]
	if !ok {
		return nil, fmt.Errorf("function not found: %d", id)
	}
	return fn, nil
}

func (s *MemoryIndexStore) GetCallers(funcID int64) ([]CallEdge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []CallEdge
	for _, edge := range s.callEdges {
		if edge.CalleeID == funcID {
			result = append(result, edge)
		}
	}
	return result, nil
}

func (s *MemoryIndexStore) GetCallees(funcID int64) ([]CallEdge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []CallEdge
	for _, edge := range s.callEdges {
		if edge.CallerID == funcID {
			result = append(result, edge)
		}
	}
	return result, nil
}

func (s *MemoryIndexStore) GetFunctionByLocation(file string, line int) (*Function, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := fmt.Sprintf("%s:%d", file, line)
	fn, ok := s.locIndex[key]
	if !ok {
		return nil, fmt.Errorf("function not found at %s:%d", file, line)
	}
	return fn, nil
}

func (s *MemoryIndexStore) GetTaintFlowsForSink(file string, line int) ([]TaintPath, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []TaintPath
	for _, flow := range s.taintFlows {
		if len(flow.Nodes) > 0 {
			sink := flow.Nodes[len(flow.Nodes)-1]
			if sink.File == file && sink.Line == line {
				result = append(result, flow)
			}
		}
	}
	return result, nil
}
