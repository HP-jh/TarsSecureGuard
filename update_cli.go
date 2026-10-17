// update_cli.go: CLI sub-command and HTTP handlers for auto-update.
// v4.15.1: unified install path + data persistence + dual channels.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/HP-jh/TarsSecureGuard/pkg/update"
)

var (
	installRoot string // set during startup from config or default
	dataRoot    string // set during startup from config or default
)

func runUpdate(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: tsg update <check|apply|rollback|channel>")
		fmt.Println("  check    - check for newer version on GitHub")
		fmt.Println("  apply    - download and apply the latest update")
		fmt.Println("  rollback - restore previous version")
		fmt.Println("  channel  - get or set release channel (stable|beta)")
		os.Exit(1)
	}
	u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard", installRoot, dataRoot)
	// Ensure stable_versions.json exists
	if _, err := u.LoadStableTable(); err != nil {
		_ = update.WriteDefaultStableTable(u.ConfigDir)
	}
	// Ensure data dirs
	_ = u.DataMgr.EnsureAll()
	_ = u.DataMgr.Migrate()

	switch args[0] {
	case "check":
		res := u.Check()
		if res.Error != "" {
			fmt.Fprintf(os.Stderr, "Check failed: %s\n", res.Error)
			fb := u.FallbackStableVersion()
			if fb != "" {
				fmt.Printf("Fallback stable version: %s\n", fb)
			}
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		if res.HasUpdate {
			fmt.Printf("\nUpdate available: %s -> %s (channel: %s)\n", res.Current, res.Latest, res.Channel)
		} else {
			fmt.Printf("\nAlready up to date (%s, channel: %s)\n", res.Current, res.Channel)
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
		time.Sleep(2 * time.Second)
	case "rollback":
		if err := u.Rollback(); err != nil {
			fmt.Fprintf(os.Stderr, "Rollback failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Rollback complete. Please restart manually.")
	case "channel":
		runUpdateChannel(u, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown update command: %s\n", args[0])
		os.Exit(1)
	}
}

func runUpdateChannel(u *update.Updater, args []string) {
	cfg, err := update.LoadChannelConfig(u.DataMgr.Sub("config"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load channel config: %v\n", err)
		os.Exit(1)
	}
	if len(args) == 0 {
		fmt.Printf("Current channel: %s\n", cfg.Channel)
		fmt.Printf("Auto-prompt: %v\n", cfg.AutoPrompt)
		fmt.Println("Usage: tsg update channel set <stable|beta>")
		return
	}
	if len(args) >= 2 && args[0] == "set" {
		ch := update.ParseChannel(args[1])
		cfg.Channel = string(ch)
		if err := update.SaveChannelConfig(u.DataMgr.Sub("config"), cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save channel: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Channel set to: %s\n", cfg.Channel)
		return
	}
	fmt.Fprintf(os.Stderr, "Usage: tsg update channel [set <stable|beta>]\n")
	os.Exit(1)
}

// startAutoUpdateCheck runs a non-blocking version check at startup.
func startAutoUpdateCheck() {
	go func() {
		u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard", installRoot, dataRoot)
		if _, err := u.LoadStableTable(); err != nil {
			_ = update.WriteDefaultStableTable(u.ConfigDir)
		}
		_ = u.DataMgr.EnsureAll()
		_ = u.DataMgr.Migrate()
		res := u.Check()
		if res.Error != "" {
			logMsg(fmt.Sprintf("[AUTO-UPDATE] Check failed: %s", res.Error))
			return
		}
		if res.HasUpdate {
			logMsg(fmt.Sprintf("[AUTO-UPDATE] New version available: %s (current %s, channel %s)", res.Latest, res.Current, res.Channel))
		} else {
			logMsg(fmt.Sprintf("[AUTO-UPDATE] Up to date (%s, channel %s)", res.Current, res.Channel))
		}
		tab, _ := u.LoadStableTable()
		if res.Latest != "" {
			tab.TarsSecureGuard = res.Latest
			_ = u.SaveStableTable(tab)
		}
		// Update last_check
		if cc, err := update.LoadChannelConfig(u.DataMgr.Sub("config")); err == nil {
			cc.LastCheck = time.Now().Format(time.RFC3339)
			_ = update.SaveChannelConfig(u.DataMgr.Sub("config"), cc)
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
			u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard", installRoot, dataRoot)
			res := u.Check()
			if res.Error != "" {
				logMsg(fmt.Sprintf("[UPDATE-DAEMON] Check failed: %s", res.Error))
				continue
			}
			if res.HasUpdate {
				logMsg(fmt.Sprintf("[UPDATE-DAEMON] New version available: %s", res.Latest))
			}
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
	u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard", installRoot, dataRoot)
	if _, err := u.LoadStableTable(); err != nil {
		_ = update.WriteDefaultStableTable(u.ConfigDir)
	}
	res := u.Check()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard", installRoot, dataRoot)
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
	u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard", installRoot, dataRoot)
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
	u := update.NewUpdater("v"+version, "HP-jh", "TarsSecureGuard", installRoot, dataRoot)
	tab, err := u.LoadStableTable()
	stable := "unknown"
	if err == nil && tab.TarsSecureGuard != "" {
		stable = tab.TarsSecureGuard
	}
	cc, _ := update.LoadChannelConfig(u.DataMgr.Sub("config"))
	installed, _ := u.InstallMgr.ListInstalled()
	current, _ := u.InstallMgr.ReadCurrent()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"current":         "v" + version,
		"stable_known":    stable,
		"channel":         cc.Channel,
		"install_root":    u.InstallMgr.Root,
		"data_root":       u.DataMgr.Root,
		"installed":       installed,
		"active_version":  current,
	})
}
