package fuzzer

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// ExecResult holds the output of an external process execution.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
}

// RunProcess executes an external command with a timeout.
// If the process exceeds timeoutSecs, it is killed and TimedOut is set to true.
func RunProcess(ctx context.Context, name string, args []string, timeoutSecs int) (*ExecResult, error) {
	if timeoutSecs <= 0 {
		timeoutSecs = 120
	}

	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &ExecResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if execCtx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ExitCode = -1
		return result, nil
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			return result, nil
		}
		return result, err
	}

	result.ExitCode = 0
	return result, nil
}
