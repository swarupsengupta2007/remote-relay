# FEAT-UTL-02: Terminal Reconnection HUD & Desktop Notifications

## 1. Executive Summary

During active OpenSSH sessions over `remote-relay`, `stdout` is exclusively dedicated to transmitting opaque SSH byte streams. When a network connection drops or fluctuates (e.g. mobile roaming or Wi-Fi handoff), `stdout` cannot be used for status messages without corrupting terminal escape sequences or binary data streams. Previously, users were left looking at a frozen terminal with no visual feedback.

**FEAT-UTL-02** introduces:
1. **TTY-Aware In-Place Status Line (HUD)**: Interactive single-line status updates rendered exclusively on `stderr` using carriage returns (`\r\033[K`), preserving 100% byte cleanliness on `stdout`.
2. **Dynamic In-Flight Diagnostics**: Displays attempt counts, transport protocols, elapsed duration, and unacknowledged backlog byte recovery upon link restoration.
3. **Cross-Terminal Desktop Notifications (OSC 9 / OSC 777)**: Emits standard ANSI terminal notification escape sequences for prolonged disconnections (>5s), compatible with Ghostty, iTerm2, WezTerm, Alacritty, and Windows Terminal.
4. **Resilient Sad-Path Safeguards**: Handles non-TTY environments (silent fallback), narrow terminal window wrapping, `NO_COLOR` compliance, and user cancellations cleanly.

---

## 2. Technical Architecture

### 2.1 State & Flow Diagram

```mermaid
sequenceDiagram
    autonumber
    actor User as Developer / Terminal
    participant Client as relay client
    participant Server as relay server

    Note over Client,Server: Active SSH session running (stdout clean)
    Server--xClient: Carrier connection drops / blackhole
    Client->>Client: Detect drop (BFD / timeout / EOF)
    Client->>User: stderr: "\r\033[K[remote-relay] Link disrupted. Reconnecting via QUIC..."

    loop Reconnect Retry Backoff
        Client->>Client: Sleep backoff schedule
        Client->>User: stderr: "\r\033[K[remote-relay] Link disrupted. Reconnecting via QUIC... (attempt 2/8, 1.4s elapsed)"
        opt Outage > 5.0s (Prolonged Disruption)
            Client->>User: stderr: OSC 9 & OSC 777 Desktop Notification
        end
    end

    alt Successful Resumption (Happy Path)
        Client->>Server: Send RESUME
        Server->>Client: Respond RESUME_OK
        Client->>User: stderr: "\r\033[K[remote-relay] Link restored via QUIC in 1.8s (resumed 34.2 KiB buffered).\n"
        Note over User,Server: Session continues seamlessly; stdout untouched
    else Fatal Error / Budget Exhaustion (Sad Path)
        Client->>User: stderr: "\r\033[K[remote-relay] Reconnection failed: reconnect budget exhausted after 8 attempts (30.1s elapsed).\n"
        Client->>User: stderr: OSC 9 & OSC 777 Failure Notification
    else User Abort (Ctrl+C / Cancel)
        Client->>User: stderr: "\r\033[K[remote-relay] Reconnection aborted: canceled by user.\n"
    end
```

---

## 3. Implementation Details

### 3.1 Terminal Detection & Environment Overrides
- **TTY Check**: Uses `golang.org/x/term.IsTerminal` on `os.Stderr.Fd()`.
- **Environment Flags**:
  - `RELAY_HUD=0`: Completely disables HUD rendering and notifications.
  - `TERM=dumb`: Automatically disables interactive HUD.
  - `NO_COLOR=1`: Automatically strips ANSI color escape codes while retaining cursor control.
- **CLI Options**:
  - `--hud`: Explicitly forces HUD activation.
  - `--no-hud`: Explicitly disables HUD.

### 3.2 Notification Protocol Support
- **OSC 9** (iTerm2, WezTerm, ConEmu):
  ```text
  \033]9;<Title>: <Message>\007
  ```
- **OSC 777** (Ghostty, Alacritty, rxvt-unicode):
  ```text
  \033]777;notify;<Title>;<Message>\007
  ```
Emitting both back-to-back ensures universal desktop notification support without native OS daemon dependencies.

### 3.3 Terminal Width Truncation
When running in narrow terminal splits (e.g. 40 or 50 columns), rendering lines longer than the terminal column count causes unwanted line wrapping. The HUD measures terminal width via `term.GetSize`, ignores non-printing ANSI escape codes, and cleanly truncates overflowing text with ellipsis (`...`) before the terminal color reset sequence.

---

## 4. Verification & Testing Matrix

### 4.1 Unit Tests (`internal/relay/hud_test.go`)
- `TestHUD_HappyPath_QuickResume`: Quick resume within 0.8s without prolonged notification.
- `TestHUD_HappyPath_RestoredZeroBytes`: Restore with 0 buffered bytes cleanly formatted without buffer clause.
- `TestHUD_HappyPath_ProlongedOutageNotifications`: Outage > 5s triggers OSC 9 and OSC 777 notifications; debouncing guarantees notification is only emitted once.
- `TestHUD_SadPath_NonTTY`: Zero bytes written when stderr is not a terminal.
- `TestHUD_SadPath_DisabledConfig`: Zero bytes written when disabled via config.
- `TestHUD_SadPath_RelayHUDEnvZero`: Zero bytes written when `RELAY_HUD=0`.
- `TestHUD_SadPath_TermDumb`: Zero bytes written when `TERM=dumb`.
- `TestHUD_SadPath_BudgetExhausted`: Red failure line and desktop notification upon timeout.
- `TestHUD_SadPath_FatalAuthError`: Clean error line on `ERR_AUTH`.
- `TestHUD_SadPath_UserCancellation`: Clean abort line on user interrupt.
- `TestHUD_SadPath_Clear`: `Clear()` properly erases line with `\r\033[K`.
- `TestHUD_SadPath_NarrowTerminalTruncation`: Lines bounded to terminal width without wrapping.
- `TestHUD_SadPath_NoColor`: `NO_COLOR=1` strips color escapes.
- `TestHUD_SadPath_BrokenWriter`: Gracefully survives `EPIPE` / write errors without panic.
- `TestHUD_SadPath_ConcurrentAccess`: 50 concurrent goroutines calling HUD methods under `-race`.
- `TestFormatBytes`: Verification of byte formatting units (`B`, `KiB`, `MiB`, `GiB`).
- `TestVisibleLenAndTruncate`: Correct visible length calculation ignoring ANSI sequences.

### 4.2 Integration Test
- `TestHUD_RunClientIntegration_StdoutIsolation`: Verified that across live carrier drops and resumptions, `stdout` remains 100% byte-exact with zero HUD bytes leaking into the SSH data stream.
