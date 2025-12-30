# DarkRelay (Phase 1)

DarkRelay is a lightweight TCP chat system built as a Rust workspace:

- `darkrelayprotocol`: shared binary protocol (bincode + serde)
- `darkrelayserver`: async Tokio server (auth, channels, broadcast)
- `darkrelayclient`: async Tokio client with a Crossterm terminal UI

> Phase 1 intentionally uses *plaintext* message bytes for testing, but the server treats message content as an opaque `Vec<u8>` blob to prepare for Phase 2 encryption.

## Quick start

### 1) Run the server

```bash
cargo run -p darkrelayserver
```

The server listens on `0.0.0.0:8080`.

Logs are written to:

- `darkrelayserver/logs/server.log`

### 2) Run the client

```bash
cargo run -p darkrelayclient
```

By default the client uses `127.0.0.1`.

## Special auth key (Phase 1)

The first step of the protocol is a **special auth key** challenge.

- Server default expected key: `darkrelay-dev-key`
- Override with env var: `DARKRELAY_SPECIAL_KEY`

## Architecture (high-level)

```
                        bincode (length-prefixed)
  ┌──────────────────────────────────────────────────────────────┐
  │                          darkrelayprotocol                    │
  │     ClientMessage / ServerMessage + ids + timestamps          │
  └──────────────────────────────────────────────────────────────┘
  ┌──────────────────────┐                     ┌──────────────────┐
  │   darkrelayclient     │                     │  darkrelayserver  │
  │  - connection.rs      │  TCP 8080           │ - handler.rs      │
  │  - ui/* (crossterm)   │ <-----------------> │ - registry.rs     │
  │  - state.rs           │                     │ - channel.rs      │
  └──────────────────────┘                     │ - auth.rs         │
                                               └──────────────────┘

 Server-side flow:
 - Accept connection -> AuthChallenge
 - Verify special key -> login/register
 - Maintain registry (active clients) and channel manager
 - Store last 100 messages/channel, return last 50 on join
```

## Commands

Inside the client input box:

- `/list` – list public channels
- `/join <name> [password]` – join (creates if missing)
- `/create <name> [password]` – alias for `/join`
- `/help` – show help
- `/quit` (or `Ctrl+C`) – disconnect and exit

## Notes

- User accounts are stored in-memory (no persistence yet).
- Channel passwords are hashed with Argon2.
- All protocol messages include a message id + timestamp.
