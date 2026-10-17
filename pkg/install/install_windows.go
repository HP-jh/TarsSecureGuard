//go:build windows
// +build windows

package install

import (
	"os/exec"
)

func init() {
	osExec = func(name string, arg ...string) *osExecCmd {
		return &osExecCmd{Cmd: name, Args: arg}
	}
}

func (c *osExecCmd) Run() error {
	return exec.Command(c.Cmd, c.Args...).Run()
}
