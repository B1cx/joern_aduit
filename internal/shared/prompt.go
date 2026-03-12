package shared

import (
	"fmt"
	"os"
	"path/filepath"
)

// PromptLoader reads prompt template files from a directory.
type PromptLoader struct {
	dir string
}

// NewPromptLoader creates a PromptLoader for the given directory.
func NewPromptLoader(dir string) *PromptLoader {
	return &PromptLoader{dir: dir}
}

// Load reads and returns the contents of a prompt file.
func (pl *PromptLoader) Load(filename string) (string, error) {
	path := filepath.Join(pl.dir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read prompt %s: %w", filename, err)
	}
	return string(data), nil
}
