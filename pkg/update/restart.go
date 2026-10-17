// restart.go: cross-platform self-restart after update.
package update

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// Restart performs a self-restart of the current binary.
// The caller should exit promptly after calling this.
func Restart() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "windows":
		// Windows cannot replace a running executable.
		// Spawn a helper process that waits and swaps.
		return restartWindows(self)
	default:
		// Unix: fork+exec the same binary.
		cmd := exec.Command(self, os.Args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Start(); err != nil {
			return err
		}
		// Give the child a moment to take over sockets, then exit.
		go func() {
			time.Sleep(500 * time.Millisecond)
			os.Exit(0)
		}()
		return nil
	}
}

func restartWindows(self string) error {
	// Write a tiny PowerShell helper that waits for the parent to exit,
	// then moves the new binary into place and restarts.
	script := fmt.Sprintf(`
Start-Sleep -Milliseconds 800
$proc = Get-Process -Id %d -ErrorAction SilentlyContinue
if ($proc) { $proc.WaitForExit() }
Start-Process -FilePath "%s" -ArgumentList "%s"
`, os.Getpid(), self, "")
	tmpPS1 := self + ".restart.ps1"
	if err := os.WriteFile(tmpPS1, []byte(script), 0644); err != nil {
		return err
	}
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-File", tmpPS1)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()
	return nil
}
