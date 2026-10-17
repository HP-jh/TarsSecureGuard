# Persistent Data Folder

v4.15.1 separates data from installation. Upgrades only switch the `current` pointer — your data never moves or gets deleted.

## Directory Layout

```
~/.tars/data/
├── config/        config.json, users.json, rbac.json, update.json
├── logs/          audit logs, runtime logs, update.log
├── cache/         temporary cache (safe to clear)
├── state/         runtime state, install history, reconcile status
├── custom/        user dictionaries, UI themes, third-party plugins
└── backup/        auto-backup of config (7-day rolling)
```

## Platform Defaults

| Platform | Default Path |
|----------|-------------|
| Linux    | `~/.tars/data/` |
| macOS    | `~/Library/Application Support/tars/data/` |
| Windows  | `%LOCALAPPDATA%\tars\data\` |
| Android  | `/data/data/<pkg>/files/tars/data/` |

## Custom Root

```bash
export TARS_DATA_ROOT=/var/lib/tars/data
# or in config.json: "dataRoot": "/var/lib/tars/data"
```

## Upgrade Invariants

- **Data directory is never touched** during an upgrade.
- New versions only **add missing files** or **add missing JSON fields**.
- Your `config.json` edits, custom dictionaries, and audit logs survive every update.

## Migration

On first startup of a new version, `data.Migrate()` runs automatically:

1. Ensures all subdirectories exist.
2. Creates `config/update.json` if missing (default channel: `stable`).
3. Never deletes or overwrites existing files.

## Uninstall

```bash
tars uninstall          # removes install/ only, keeps data/
tars uninstall --purge  # removes both install/ and data/
```

## Backup

Config is auto-backedup before every upgrade with nanosecond-precision timestamps. Only the last 7 backups are kept.
