# Release Channels

v4.15.1 introduces **Stable** and **Beta** release channels. Users choose their preferred channel via settings or CLI.

## Channel Comparison

| Aspect | Stable | Beta |
|--------|--------|------|
| Trigger | Major bump only (v4.x.0, v5.0.0) | Any release (patch, minor, prerelease) |
| Notification | Modal dialog on startup | Toast notification on startup |
| Download | User clicks "Update" | User clicks "Details" or auto-downloads |
| Default | Conservative users, enterprise | Personal users, developers |

## How It Works

A release is considered **Stable** when:
- Major version changes (v4 → v5), OR
- Minor version changes with patch == 0 (v4.15.0 → v4.16.0)

Everything else (patch bumps, prereleases) is **Beta**.

## Switching Channels

### CLI

```bash
# View current channel
tsg update channel

# Set channel
tsg update channel set stable
tsg update channel set beta
```

### Config File

Edit `data/config/update.json`:

```json
{
  "channel": "stable",
  "last_check": "2026-10-18T06:30:00Z",
  "auto_prompt": true
}
```

### Admin UI

The update status endpoint (`/api/admin/update/status`) returns the current channel:

```json
{
  "current": "v4.15.1",
  "channel": "stable",
  "installed": ["4.15.1", "4.15.0", "4.14.0"],
  "active_version": "4.15.1"
}
```

## GitHub Release Metadata

Each release description includes:

```yaml
channel: stable   # or beta
major: 4
```

The client uses this metadata together with local semver parsing to determine channel eligibility.

## Cross-Repository

All 6 Tars repositories share the `tars-update` library and support dual channels independently:

- TSG
- TarsEnterprise
- TarsUITarsBridge
- TarsOpenClawSandbox
- TarsWingGuard
- TarsVoiceCorrection
