package execx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Runner abstracts command execution so packages can be unit-tested without
// touching real system networking (ip/wg).
type Runner interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) (string, error)
}

// OSRunner executes commands on the host via os/exec.
type OSRunner struct {
	Stdout io.Writer
	Stderr io.Writer
}

func NewOSRunner(stdout, stderr io.Writer) *OSRunner {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	return &OSRunner{Stdout: stdout, Stderr: stderr}
}

func (r *OSRunner) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = r.Stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s: %s", err.Error(), msg)
		}
		return err
	}
	if stderr.Len() > 0 && r.Stderr != nil {
		_, _ = io.Copy(r.Stderr, &stderr)
	}
	return nil
}

func (r *OSRunner) Output(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if err != nil {
		return "", errors.New(buf.String())
	}
	return strings.TrimSpace(buf.String()), nil
}
