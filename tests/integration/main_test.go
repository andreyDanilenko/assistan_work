package integration_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binary string

// Exercise startup through the real executable, without exposing main's helpers.
func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "lokictl-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binary = filepath.Join(directory, "lokictl")
	build := exec.Command("go", "build", "-o", binary, "./cmd/lokictl")
	build.Dir = "../.."
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(directory)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(directory)
	os.Exit(code)
}

func runCLI(ctx context.Context, args []string, output, diagnostic io.Writer) int {
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdout, command.Stderr = output, diagnostic
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		fmt.Fprintln(diagnostic, "CLI process failed:", err)
		return 1
	}
	return 0
}
