package orchestrator

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// DiffFilter holds the set of changed files from a git diff.
type DiffFilter struct {
	changedFiles map[string]bool // relative file paths that changed
}

// NewDiffFilter runs git diff against the given ref and extracts changed file paths.
func NewDiffFilter(targetDir, diffRef string) (*DiffFilter, error) {
	cmd := exec.Command("git", "diff", "--name-only", diffRef)
	cmd.Dir = targetDir

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only %s: %w", diffRef, err)
	}

	files := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files[line] = true
			// Also store absolute path
			absPath := filepath.Join(targetDir, line)
			files[absPath] = true
		}
	}

	return &DiffFilter{changedFiles: files}, nil
}

// Contains checks if the given file path is in the diff set.
func (df *DiffFilter) Contains(filePath string) bool {
	if df.changedFiles[filePath] {
		return true
	}
	// Try basename match for paths with different prefixes
	base := filepath.Base(filePath)
	for f := range df.changedFiles {
		if filepath.Base(f) == base && strings.HasSuffix(f, filePath) {
			return true
		}
	}
	return false
}

// Count returns the number of changed files.
func (df *DiffFilter) Count() int {
	return len(df.changedFiles) / 2 // each file stored as both relative and absolute
}
