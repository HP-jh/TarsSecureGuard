# Unified Install Paths

v4.15.1 introduces a unified install directory where every version coexists as a sibling subdirectory.

## Directory Layout

```
~/.tars/install/
├── current -> 4.15.1/          (symlink/junction to active version)
├── 4.14.0/
│   └── TarsSecureGuard
├── 4.15.0/
│   └── TarsSecureGuard
└── 4.15.1/
    └── TarsSecureGuard
```

## Platform Defaults

| Platform | Default Path |
|----------|-------------|
| Linux    | `~/.tars/install/{version}/` |
| macOS    | `~/Library/Application Support/tars/install/{version}/` |
| Windows  | `%LOCALAPPDATA%\tars\install\{version}\` |
| Android  | `/data/data/<pkg>/files/tars/install/{version}/` |

## Custom Root

Set via config or environment:

```bash
# Environment variable
export TARS_INSTALL_ROOT=/opt/tars/install

# Or in config.json
{
  "installRoot": "/opt/tars/install"
}
```

## Upgrade Behavior

- **Never modifies** an existing version directory.
- New version downloads to `install/{new.version}/`.
- After SHA256 verification, `current` symlink switches to the new directory.
- Old versions remain intact for instant rollback.

## CLI

```bash
tsg update check     # check for update
tsg update apply     # download and switch current pointer
tsg update rollback  # switch current back to previous version
```
