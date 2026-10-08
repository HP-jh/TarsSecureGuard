# TarsSecureGuard v4.1.0 Changelog

## Release Date
2026-10-08

## Overview
v4.1.0 introduces three major feature sets:
1. **Multi-Agent Collaboration** - Agents across clients cooperate via Crown Bus
2. **MCP Tool Integration** - Model Context Protocol support with RBAC + quota + audit
3. **Distributed Device Mesh (mini SkyOS)** - Cross-device discovery, content addressing, encrypted messaging

## New Modules

### crownext/agentmesh - Multi-Agent Collaboration
- `AgentCard` - Identity & capability manifest (ID, version, tools, domains, RBAC role, quota)
- `Registry` - Thread-safe local + remote agent registry with capability-based lookup
- `Dispatcher` - Task routing with local execution and remote stub
- `PatternSupervisor` - Split/aggregate worker pattern
- `PatternP2P` - Direct peer-to-peer delegation
- `PatternBroadcast` - Fan-out to all capable agents

### crownext/mcpclient - MCP Client with Guard
- `Registry` - MCP tool registration with `ToolPolicy` (RBAC roles, rate limits, confirmation)
- `Guard` - Triple-gate: RBAC + quota + audit for every invocation
- Capped audit log (10,000 records) with per-role/per-tool call tracking

### crownext/mcpserver - MCP Server
- JSON-RPC 2.0 HTTP endpoint (`initialize`, `tools/list`, `tools/call`)
- Pluggable `ToolHandler` registry

### crownext/skylink - Distributed Device Mesh
- `DeviceProfile` - Typed device manifest (phone/pc/server/edge) with capability advertisement
- `Discovery` - Peer discovery table with trusted/untrusted distinction and pruning
- `ContentStore` - Lightweight CAS using SHA-256 CIDs with pin/unpin/GC
- `Messenger` - AES-256-GCM encrypted device-to-device messaging
- `CoordClient` - Distributed coordination with Watch/Lease/Election (etcd-compatible interface)

### crownext/threatmodel - Security Primitives
- `DeviceAuthManager` - ECDSA P-256 mutual authentication with ephemeral CA
- `ContentVerifier` - CID verification + lightweight Merkle tree
- `Isolator` - Quarantine with auto-escalation (rate_limit -> quarantine -> block)

## Security
- All cross-device messages encrypted with AES-256-GCM using per-peer shared keys
- Device certificates use ECDSA P-256 with CN-based peerID validation
- MCP tool invocation requires RBAC authorization, rate-limiting, and audit logging
- Untrusted devices automatically isolated with escalating severity
- No unencrypted channels; no裸HTTP in cross-device paths

## Compatibility
- Built on Crown Bus (v4.0.0-rewrite) envelope/pipeline architecture
- 33 retained contracts preserved (RBAC 7x9 matrix, hash-chain audit, sensitive interface auth)
- Stdlib-only build; interfaces designed for later plug-in of libp2p, etcd, MCP SDK

## Tests
- Unit tests for all 5 packages (agentmesh, mcpclient, mcpserver, skylink, threatmodel)
- Race-detector clean (`go test -race ./...`)
- End-to-end integration test covering multi-agent + MCP + cross-device scenarios

## Binary
- `tsg-v4.1.0-linux-amd64` - Demo binary exercising all v4.1.0 modules

## SHA256
```
212e1348fcb9408ef17a66b0ad86abab1aab2b3e7ab57542b8f68bf9c1651101  tsg-v4.1.0-linux-amd64
```
