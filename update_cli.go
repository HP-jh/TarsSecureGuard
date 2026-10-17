// update_cli.go: CLI sub-command and HTTP handlers for auto-update.
// v4.15.0
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/HP-jh/TarsSecureGuard/pkg/update"
)

func runUpdate(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: tsg update <check|apply|rollback>")
		fmt.Println("  check    - check for newer version on GitHub")
		fmt.Println("  apply    - download and apply the latest update")
		fmt.Println("  rollback - restore previous binary backup")
		os.Exit(1)
	}
	u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard")
	// Ensure stable_versions.json exists
	if _, err := u.LoadStableTable(); err != nil {
		_ = update.WriteDefaultStableTable(u.ConfigDir)
	}

	switch args[0] {
	case "check":
		res := u.Check()
		if res.Error != "" {
			fmt.Fprintf(os.Stderr, "Check failed: %s\n", res.Error)
			// fallback
			fb := u.FallbackStableVersion()
			if fb != "" {
				fmt.Printf("Fallback stable version: %s\n", fb)
			}
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		if res.HasUpdate {
			fmt.Printf("\nUpdate available: %s -> %s\n", res.Current, res.Latest)
		} else {
			fmt.Printf("\nAlready up to date (%s)\n", res.Current)
		}
	case "apply":
		res := u.Check()
		if res.Error != "" {
			fmt.Fprintf(os.Stderr, "Check failed: %s\n", res.Error)
			os.Exit(1)
		}
		if !res.HasUpdate {
			fmt.Println("No update available.")
			return
		}
		fmt.Printf("Applying update %s -> %s ...\n", res.Current, res.Latest)
		if err := u.Apply(res); err != nil {
			fmt.Fprintf(os.Stderr, "Apply failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Update applied. Restarting...")
		if err := update.Restart(); err != nil {
			fmt.Fprintf(os.Stderr, "Restart failed: %v\n", err)
			os.Exit(1)
		}
		// Wait for restart to take over
		time.Sleep(2 * time.Second)
	case "rollback":
		if err := u.Rollback(); err != nil {
			fmt.Fprintf(os.Stderr, "Rollback failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Rollback complete. Please restart manually.")
	default:
		fmt.Fprintf(os.Stderr, "Unknown update command: %s\n", args[0])
		os.Exit(1)
	}
}

// startAutoUpdateCheck runs a non-blocking version check at startup.
func startAutoUpdateCheck() {
	go func() {
		u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard")
		if _, err := u.LoadStableTable(); err != nil {
			_ = update.WriteDefaultStableTable(u.ConfigDir)
		}
		res := u.Check()
		if res.Error != "" {
			logMsg(fmt.Sprintf("[AUTO-UPDATE] Check failed: %s", res.Error))
			return
		}
		if res.HasUpdate {
			logMsg(fmt.Sprintf("[AUTO-UPDATE] New version available: %s (current %s)", res.Latest, res.Current))
		} else {
			logMsg(fmt.Sprintf("[AUTO-UPDATE] Up to date (%s)", res.Current))
		}
		// Save stable table on successful check
		tab, _ := u.LoadStableTable()
		if res.Latest != "" {
			tab.TarsSecureGuard = res.Latest
			_ = u.SaveStableTable(tab)
		}
	}()
}

// startUpdateDaemon runs a 24h periodic update check.
func startUpdateDaemon() {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			<-ticker.C
			u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard")
			res := u.Check()
			if res.Error != "" {
				logMsg(fmt.Sprintf("[UPDATE-DAEMON] Check failed: %s", res.Error))
				continue
			}
			if res.HasUpdate {
				logMsg(fmt.Sprintf("[UPDATE-DAEMON] New version available: %s", res.Latest))
			}
			// Refresh stable table
			tab, _ := u.LoadStableTable()
			if res.Latest != "" {
				tab.TarsSecureGuard = res.Latest
				_ = u.SaveStableTable(tab)
			}
		}
	}()
}


// HTTP handlers for admin UI
func handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard")
	if _, err := u.LoadStableTable(); err != nil {
		_ = update.WriteDefaultStableTable(u.ConfigDir)
	}
	res := u.Check()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard")
	res := u.Check()
	if res.Error != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": res.Error})
		return
	}
	if !res.HasUpdate {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "no update available"})
		return
	}
	if err := u.Apply(res); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "update applied, restarting..."})
	go func() {
		time.Sleep(1 * time.Second)
		_ = update.Restart()
	}()
}

func handleUpdateRollback(w http.ResponseWriter, r *http.Request) {
	u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard")
	if err := u.Rollback(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "rollback complete, please restart manually"})
}

func handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard")
	tab, err := u.LoadStableTable()
	stable := "unknown"
	if err == nil && tab.TarsSecureGuard != "" {
		stable = tab.TarsSecureGuard
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"current":      "v" + version,
		"stable_known": stable,
		"config_dir":   u.ConfigDir,
	})
}
