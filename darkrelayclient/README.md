# DarkRelay Client

A secure, terminal-based chat client for the DarkRelay messaging system with support for encrypted channels, direct messages, file transfers, and federation.

## Features

### Phase 1: Basic Channels
- ✅ TLS connection to server
- ✅ Channel listing and joining
- ✅ Real-time messaging
- ✅ User authentication (login/register)

### Phase 2: Encryption
- ✅ ECDH key exchange with server
- ✅ AES-256-GCM message encryption
- ✅ Per-channel password-based encryption (PBKDF2)
- ✅ 🔒 encryption indicator in UI

### Phase 3: Admin Features
- ✅ User role management (promote/demote)
- ✅ Moderation commands (ban/kick)
- ✅ Message deletion
- ✅ Admin command support

### Phase 4: Direct Messages & File Transfer
- ✅ Direct message support (local and federated)
- ✅ DM history loading
- ✅ File transfer proposals and status tracking
- ✅ Unread message indicators

### Phase 5: Federation
- ✅ Cross-server user identification
- ✅ Federated DM support (`username@server_id`)
- ✅ Federation-aware message handling

## Installation

### Prerequisites
- Rust 1.70+ (install from https://rustup.rs/)
- Linux, macOS, or Windows 10/11

### Building

```bash
cd darkrelayclient
cargo build --release
```

The compiled binary will be at `target/release/darkrelayclient`.

## Usage

### Starting the Client

```bash
./target/release/darkrelayclient
```

Or with custom environment variables:

```bash
DARKRELAY_SPECIAL_KEY="your-secret-key" ./target/release/darkrelayclient
```

### Authentication Dialog

When you start the client, you'll see an authentication dialog:

1. **Server IP**: Enter the server address (default: `127.0.0.1`)
2. **Username**: Your username
3. **Password**: Your password (only for login)
4. **Buttons**: 
   - `Login` - Log in with existing credentials
   - `Register` - Create new account (server generates password)
   - `Exit` - Quit the application

**Navigation**:
- `Tab` / `Shift+Tab` - Move between fields
- `Left` / `Right` - Select button
- `Enter` - Submit
- `Ctrl+C` / `Esc` - Exit

### Main Interface

After authentication, you'll see a 3-pane layout:

```
┌─────────────────────────────────────────────────────────────┐
│ DarkRelay 🔒 | Connected: alice @ 127.0.0.1:8080            │
├────────────┬──────────────────────────────┬─────────────────┤
│ Channels   │ Messages (general)           │ Info            │
│            │                               │                 │
│ # general  │ [14:30:22] <alice>: hello    │ /help           │
│   lobby    │ [14:30:35] <bob>: hi there   │ /list           │
│   random   │                               │ /join <name>    │
│            │                               │ /quit           │
│            │                               │                 │
│            │                               │                 │
├────────────┴──────────────────────────────┴─────────────────┤
│ > Type your message here...                                 │
└─────────────────────────────────────────────────────────────┘
```

**Panes**:
- **Left (Channels)**: List of available channels. Your current channel is marked with `#`.
- **Center (Messages)**: Message history for the current channel.
- **Right (Info)**: Command help and channel information.
- **Bottom (Input)**: Type messages and commands here.

**Navigation**:
- `Left` / `Right` - Switch focus between channel list and input
- `Up` / `Down` - Navigate channel list (when focused)
- `Enter` - Join selected channel or send message
- `Esc` / `Ctrl+C` - Disconnect and return to auth dialog

## Commands

### Channel Commands

| Command | Description | Example |
|---------|-------------|---------|
| `/list` | Show all available channels | `/list` |
| `/join <channel> [password]` | Join or create a channel | `/join general` |
| `/create <channel> [password]` | Alias for `/join` | `/create secret mypassword` |
| `/quit` or `/exit` | Disconnect from server | `/quit` |
| `/help` | Show command list | `/help` |

### Admin Commands

These commands require appropriate permissions (Admin or Moderator role):

| Command | Description | Example |
|---------|-------------|---------|
| `/promote <user> <role>` | Promote user to admin or moderator | `/promote alice admin` |
| `/demote <user>` | Demote user to regular role | `/demote bob` |
| `/ban <user> [reason]` | Ban user from channel | `/ban troll spamming` |
| `/kick <user> [reason]` | Kick user from channel | `/kick alice timeout` |
| `/delete <message_id>` | Delete a message | `/delete 12345` |

**Valid roles**: `admin`, `moderator` (or `mod`)

### Direct Message Commands

| Command | Description | Example |
|---------|-------------|---------|
| `/dm <username>` | Open DM with user | `/dm alice` |
| `/dm <username@server>` | Open federated DM | `/dm bob@123` |

> **Note**: Full DM UI integration is in progress. Currently, DMs are received and stored, but you'll need to check notifications.

### File Transfer Commands

| Command | Description | Example |
|---------|-------------|---------|
| `/file send <user> <path>` | Send file to user | `/file send alice /path/to/file.txt` |
| `/files` | Show active transfers | `/files` |

> **Note**: File transfer commands are in development. You'll receive notifications when files are proposed.

## Encryption

### End-to-End Encryption

The client automatically performs ECDH key exchange with the server on connection:

1. Client generates ephemeral keypair
2. Exchanges public keys with server
3. Derives shared AES-256-GCM key
4. All messages are encrypted/decrypted transparently

When encryption is active, you'll see a 🔒 icon in the header.

### Channel Passwords

When creating/joining a password-protected channel, an additional encryption layer is applied:

```bash
/join secret mypassword
```

Messages in this channel are double-encrypted:
1. Channel password (PBKDF2 → AES-256-GCM)
2. Server ECDH shared secret (AES-256-GCM)

### Message Format

Encrypted messages are automatically decrypted when displayed. If decryption fails, you'll see `[decryption failed]`.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DARKRELAY_SPECIAL_KEY` | `darkrelay-dev-key` | Server authentication key |
| `RUST_LOG` | `info` | Logging level (`error`, `warn`, `info`, `debug`, `trace`) |

### Logging

Logs are written to stderr (not visible in the UI). To view logs:

```bash
RUST_LOG=debug ./darkrelayclient 2> client.log
```

Then in another terminal:
```bash
tail -f client.log
```

## Troubleshooting

### Connection Failed

**Symptom**: "Connection failed: Connection refused"

**Solutions**:
- Verify the server is running on the specified IP and port (default: 8080)
- Check firewall settings
- Try connecting to `127.0.0.1` for local server

### Authentication Failed

**Symptom**: "Auth failed: Invalid credentials"

**Solutions**:
- Verify `DARKRELAY_SPECIAL_KEY` matches the server's key
- For login, ensure username and password are correct
- For registration, use a unique username

### Decryption Failed

**Symptom**: Messages show as `[decryption failed]`

**Causes**:
- Joined channel with wrong password
- Message sent before ECDH handshake completed
- Network corruption (rare)

**Solutions**:
- Rejoin the channel with correct password
- Wait a moment after connecting before sending messages

### Terminal Issues

**Symptom**: Garbled output or keyboard not working

**Solutions**:
- Ensure your terminal supports ANSI escape codes
- Try resizing the terminal window
- Press `Ctrl+C` to exit and restart
- On Linux: Ensure `TERM` is set correctly (`echo $TERM`)

### Performance

**Symptom**: UI lag or high CPU usage

**Solutions**:
- Reduce `RUST_LOG` verbosity (use `warn` or `error`)
- Clear terminal history periodically
- Limit active channels (max 10-20 recommended)

## Platform-Specific Notes

### Linux
- Works on all major distributions (Ubuntu, Fedora, Arch, etc.)
- Requires `libssl-dev` (usually installed by default)
- Test on both X11 and Wayland terminals

### macOS
- Works on macOS 10.15+ (Catalina and newer)
- Use Terminal.app or iTerm2
- On Apple Silicon, compiles natively for `aarch64`

### Windows
- Works on Windows 10/11 with Windows Terminal or PowerShell
- WSL (Windows Subsystem for Linux) also supported
- Avoid legacy cmd.exe (use PowerShell or Windows Terminal)

## Development

### Running Tests

```bash
cargo test
```

### Code Structure

```
src/
├── main.rs           # Entry point, auth flow
├── connection.rs     # TLS connection management
├── crypto.rs         # Encryption (ECDH, AES-GCM)
├── state.rs          # Client state management
├── dm_handler.rs     # DM conversation tracking
└── ui/               # Terminal UI
    ├── mod.rs        # Terminal session
    ├── auth_dialog.rs    # Login/register dialog
    ├── main_layout.rs    # Main 3-pane interface
    ├── dm_view.rs        # DM conversation view (ratatui)
    └── file_dialog.rs    # File transfer dialog (ratatui)
```

### Adding Features

1. **New Commands**: Add to `handle_command()` in `ui/main_layout.rs`
2. **Server Messages**: Add to `handle_server_message()` in `ui/main_layout.rs`
3. **UI Components**: Create in `ui/` directory (use `crossterm` or `ratatui`)
4. **State**: Extend `ClientState` in `state.rs`

### Debugging

Enable trace logging:

```bash
RUST_LOG=darkrelayclient=trace cargo run 2> debug.log
```

View protocol messages:
```bash
RUST_LOG=darkrelayclient::connection=trace cargo run
```

## Security Considerations

### TLS
- Server certificates are **not validated** (accepts self-signed)
- Suitable for testing/development only
- For production, implement proper certificate validation in `connection.rs`

### Key Storage
- ECDH keys are ephemeral (generated per session)
- No persistent key storage (you must log in each time)
- Generated passwords from registration are shown once - save them securely

### Message Security
- All messages are encrypted in transit (TLS) and at rest (AES-GCM)
- Server has access to plaintext (not end-to-end between users)
- Channel passwords provide an additional layer vs. server

## FAQ

**Q: Can I use DarkRelay on mobile?**  
A: Not currently. DarkRelay is terminal-only. A mobile client would need to be built separately.

**Q: Are messages stored on the server?**  
A: Yes, encrypted messages are stored server-side. Channel history persists across sessions.

**Q: Can I run multiple clients at once?**  
A: Yes, you can run multiple instances. Each maintains its own connection.

**Q: How do I change my password?**  
A: Password management is not yet implemented. Contact your server admin.

**Q: What's the maximum message size?**  
A: Currently limited by the protocol frame size (typically a few KB). Large data should use file transfer.

**Q: Can I use Markdown or formatting?**  
A: Not currently. Plain text messages only.

## Contributing

This project is part of the DarkRelay system. Contributions welcome:

1. Fork the repository
2. Create a feature branch
3. Make your changes (ensure `cargo test` passes)
4. Submit a pull request

Please follow existing code style and add tests for new features.

## License

See `LICENSE` file in the repository root.

## Credits

Built with:
- [rustls](https://github.com/rustls/rustls) - TLS implementation
- [crossterm](https://github.com/crossterm-rs/crossterm) - Terminal manipulation
- [ratatui](https://github.com/ratatui-org/ratatui) - Terminal UI framework (for modals)
- [tokio](https://tokio.rs/) - Async runtime
- [x25519-dalek](https://github.com/dalek-cryptography/x25519-dalek) - ECDH key exchange
- [aes-gcm](https://github.com/RustCrypto/AEADs) - AES-256-GCM encryption

## Support

For issues, questions, or feature requests, please file an issue on the project repository.
