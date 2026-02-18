package verifier

// AgentContract defines the constraints for any agent in the verification pipeline.
type AgentContract struct {
	// MaxTurns limits the number of LLM round-trips.
	MaxTurns int `json:"max_turns"`

	// MaxToolCalls limits total tool invocations.
	MaxToolCalls int `json:"max_tool_calls"`

	// SearchPaths constrains which directories the agent may search.
	SearchPaths []string `json:"search_paths"`

	// ExcludePaths are directories to never search.
	ExcludePaths []string `json:"exclude_paths"`

	// TurnReserve forces the agent to stop exploring and produce output
	// when turns_used >= max_turns - TurnReserve.
	TurnReserve int `json:"turn_reserve"`

	// MaxSinkCategories limits how many sink categories per dimension.
	MaxSinkCategories int `json:"max_sink_categories"`

	// MaxInstancesPerSink limits deep-trace instances per sink category.
	MaxInstancesPerSink int `json:"max_instances_per_sink"`

	// TokenBudget is the max tokens for the entire agent session.
	TokenBudget int `json:"token_budget"`
}

// DefaultAgentContract returns sensible defaults for agent constraints.
func DefaultAgentContract() AgentContract {
	return AgentContract{
		MaxTurns:            25,
		MaxToolCalls:        50,
		TurnReserve:         3,
		MaxSinkCategories:   8,
		MaxInstancesPerSink: 3,
		TokenBudget:         8000,
		ExcludePaths: []string{
			"node_modules", ".git", "build", "dist",
			"target", "vendor", "test", "tests",
		},
	}
}
