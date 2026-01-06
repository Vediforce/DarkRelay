# DarkRelay Client - Quick Start Guide

## Installation

### 1. Build the Client

```bash
cd darkrelayclient
cargo build --release
```

The binary will be at: `target/release/darkrelayclient`

### 2. Run the Client

```bash
./target/release/darkrelayclient
```

Or from the project root:
```bash
cargo run -p darkrelayclient
```

## First Time Setup

### Authentication Dialog

When you start the client, you'll see:

```
DarkRelay v1.0

Server IP:  > 127.0.0.1
Username:     alice
Password:     ********

[Login]  Register  Exit
```

**Steps**:
1. Enter server IP (default: 127.0.0.1 for local)
2. Tab to Username, enter your username
3. Tab to Password
   - If **registering**: Leave blank, server generates password
   - If **logging in**: Enter your password
4. Tab to buttons, use arrow keys to select Login/Register
5. Press Enter

### Registration
- Server generates a secure password
- **IMPORTANT**: Save this password! It's shown only once
- Use it for future logins

### Login
- Enter your username and password
- If forgotten, contact server admin for reset

## Using the Client

### Main Interface

```
┌────────────────────────────────────────────────────────┐
│ DarkRelay 🔒 | Connected: alice @ 127.0.0.1:8080       │ ← Header
├──────────┬──────────────────────┬─────────────────────┤
│ Channels │ Messages (general)   │ Commands:           │
│          │                      │ /help               │
│ # general│ [14:30] <alice>: hi  │ /list               │
│   lobby  │ [14:31] <bob>: hey   │ /join <name>        │
│   random │                      │ /dm <user>          │
│          │                      │ /promote            │
│          │                      │ /ban <user>         │
│          │                      │ /quit               │
├──────────┴──────────────────────┴─────────────────────┤
│ > Type your message...                                 │ ← Input
└────────────────────────────────────────────────────────┘
```

### Navigation

| Key | Action |
|-----|--------|
| `Left` / `Right` | Switch focus (channels ↔ input) |
| `Up` / `Down` | Navigate channel list (when focused) |
| `Enter` | Join selected channel OR send message |
| `Esc` / `Ctrl+C` | Disconnect and return to auth |

## Essential Commands

### Getting Started

```bash
/list                  # Show all channels
/join general          # Join the "general" channel
Hello everyone!        # Send a message (no command prefix)
/quit                  # Disconnect
```

### Channel Management

```bash
/join lobby            # Join or create "lobby"
/join secret mypass    # Join password-protected channel
/create private pass123 # Create new password-protected channel
```

### Messaging

- Just type and press Enter to send
- Messages are automatically encrypted
- 🔒 icon shows encryption is active
- Your messages appear in **cyan**
- Others' messages in white

### Admin Commands (requires permissions)

```bash
/promote bob admin     # Make bob an admin
/promote alice mod     # Make alice a moderator
/demote bob            # Remove bob's admin status
/ban troll spamming    # Ban user "troll" with reason
/kick alice timeout    # Kick alice temporarily
/delete 12345          # Delete message with ID 12345
```

### Direct Messages (in development)

```bash
/dm alice              # Open DM with alice (local)
/dm bob@123            # Open DM with bob on server 123 (federated)
```

*Note: DM backend works, but UI switching is not yet implemented. You'll see notifications when DMs arrive.*

## Tips & Tricks

### Keyboard Shortcuts
- `Tab` in auth dialog: Move between fields
- `Left/Right`: Focus channels or input
- `Up/Down`: Navigate channel list
- `Enter`: Join channel or send message

### Terminal Size
- **Large (120+ cols)**: 3-pane layout (channels | messages | info)
- **Medium (80-120)**: 2-pane layout (channels | messages)
- **Small (<80)**: Single pane (resize for best experience)

### Best Practices
1. **Save your password** after registration (it's shown only once)
2. **Use /help** to see available commands
3. **Join channels** before sending messages
4. **Resize terminal** if layout looks cramped (recommended: 120x40)
5. **Check toasts** in top-right for notifications

### Troubleshooting

**Problem**: "Connection failed"
- **Solution**: Verify server is running on specified IP:8080

**Problem**: "Auth failed"
- **Solution**: Check `DARKRELAY_SPECIAL_KEY` matches server's key

**Problem**: "[decryption failed]" in messages
- **Solution**: Rejoin channel with correct password

**Problem**: Terminal looks garbled
- **Solution**: Press `Ctrl+C` to exit, restart client
- Ensure terminal supports ANSI colors (use Windows Terminal, iTerm2, or modern Linux terminal)

## Environment Variables

### Optional Configuration

```bash
# Set server authentication key (must match server)
export DARKRELAY_SPECIAL_KEY="your-secret-key"

# Enable debug logging
export RUST_LOG=darkrelayclient=debug

# Run with custom settings
./target/release/darkrelayclient
```

### Logging

View logs in separate terminal:
```bash
# Terminal 1: Run client with log output
RUST_LOG=debug ./target/release/darkrelayclient 2> client.log

# Terminal 2: Watch logs
tail -f client.log
```

## Common Workflows

### Joining and Chatting

```bash
# 1. Start client
./target/release/darkrelayclient

# 2. Auth dialog: enter IP, username, select Register
# 3. Save generated password

# 4. In main UI:
/list                    # See available channels
/join general            # Join general channel
Hello!                   # Send message
How's everyone?          # Send another message
/quit                    # Disconnect
```

### Creating a Private Channel

```bash
/create mychannel secretpass   # Create with password
/join mychannel secretpass     # Others join with password
This is private!               # Only members see this
```

### Admin Tasks

```bash
/join general                  # Must be in channel
/promote alice admin           # Make alice an admin
/ban troll reason here         # Ban a user
/kick alice goodbye            # Kick user
```

## Next Steps

1. **Explore Commands**: Try `/help` to see all commands
2. **Test Encryption**: Look for 🔒 icon in header
3. **Try DMs**: Use `/dm username` (notifications will appear)
4. **Admin Features**: If you're admin, try `/promote`, `/ban`
5. **Federation**: Try messaging users on other servers with `@server_id`

## Getting Help

- **In Client**: Type `/help`
- **Issues**: Check `IMPLEMENTATION_SUMMARY.md`
- **Full Docs**: See `README.md`

## Security Reminder

⚠️ **Development Mode**:
- Server uses self-signed TLS certificates (accepted automatically)
- For production, implement proper certificate validation
- All messages encrypted in transit and at rest
- Server can see plaintext (not end-to-end between users)

## Have Fun!

DarkRelay is a secure, terminal-based chat system. Enjoy exploring its features and happy chatting! 🚀
