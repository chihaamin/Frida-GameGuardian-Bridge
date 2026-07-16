# Frida GameGuardian Bridge (FGGB)

**Use Frida from inside GameGuardian Lua scripts.** FGGB injects a `frida` global into
GameGuardian's (GG) embedded Lua — right next to `gg` — so a GG script can attach Frida to
**the process GG is currently targeting** and run real instrumentation (Interceptor,
Memory, Module, Stalker) on it:

```lua
gg.alert(frida.base("libil2cpp.so"))                 -- module base in GG's target
local a = frida.export("libc.so", "open")
local sid = frida.hook(a)                             -- log every open() call
-- ... play the game ...
gg.alert(frida.pull(sid))                             -- read the captured calls
```

No HTTP, no separate app — FGGB is a small root binary that runs on the device.

> **NOTE: aarch64 Android, rooted.**

## How it works

```
GG Lua:  frida.hook(addr)
   │  (runs on GG's script thread; reads gg.getTargetInfo().pid)
   ▼  send() request + block on reply   [Frida message channel]
FGGB  (Rust, frida-core 17, runs as root)
   ├─ injected the `frida` bridge into GG's process (LuaJ)
   └─ attaches Frida to GG's TARGET, runs the code there, streams results back
        ▼
GG Lua:  <- result / frida.pull(sid) for later events
```

- **FGGB** is a resident controller. It discovers GG (by the `version.gg` marker), injects
  the bridge agent into GG's process, and re-injects if GG restarts.
- The **bridge agent** registers the `frida` table into GG's LuaJ `Globals` (and every new
  script env). Each `frida.*` call marshals to FGGB, which does the actual Frida work in the
  target and replies — all over Frida's own message channel.
- FGGB uses frida-core's **local device** (its own embedded frida-core, as root), so it needs
  **no frida-server** and there's no client/server version to match.

## The `frida` API (inside GG scripts)

Everything except `version`/`help`/`runpid` operates on **GG's current target**
(`gg.getTargetInfo().pid`) — select a process in GG first.

| Call | Returns |
|---|---|
| `frida.target()` | GG's current target pid |
| `frida.modules([filter])` | target's loaded modules — `name base size` (optional name filter) |
| `frida.base(module)` | base address of a module |
| `frida.export(module, symbol)` | address of an exported symbol |
| `frida.read(addr, len)` | `len` bytes at `addr` as hex |
| `frida.write(addr, "AA BB ..")` | write hex bytes at `addr` |
| `frida.scan("AA ?? CC")` | addresses matching a byte pattern (`??` = wildcard) |
| `frida.hook(addr)` | install a logging Interceptor; returns `[session N]`; drain hits with `pull` |
| `frida.run(js)` | run arbitrary Frida JS in the target; returns `[session N]` + its `send()` output |
| `frida.pull(sid)` | drain buffered events (hook hits, `send()`s) from session `sid` |
| `frida.kill(sid)` | detach a session |
| `frida.runpid("pid\|js")` | run js in an **explicit** pid (escape hatch, ignores GG's target) |
| `frida.version()` / `frida.help()` | Frida version / API cheatsheet |

Read/list ops are one-shot (FGGB attaches, runs, detaches). `run`/`hook` keep a session
alive so hooks persist and their events are read later with `pull(sid)`.

See **[docs/frida-api.md](docs/frida-api.md)** for details and **[examples/fggb.lua](examples/fggb.lua)** for a full script.

## Requirements & limitations

- **The target must be Frida-attachable.** FGGB *injects an agent* into the target (unlike
  GG, which only reads/writes memory via `process_vm_readv`). Games with **anti-Frida /
  anti-debug protection can block late attach** — e.g. Grim Soul returns an attach error.
  For such targets you need spawn-time instrumentation or an anti-tamper bypass (not yet
  built). FGGB works fine on unprotected apps/processes.
- **Target-side runs core Gum** (Interceptor / Memory / Module / Stalker / NativePointer).
  Hooking **Java** *in the target* would require bundling the Java bridge into the injected
  code — not done yet.
- **Hook events are polled** via `frida.pull(sid)`, not delivered as live Lua callbacks.
- GG must have `gg.getTargetInfo` (present in modern GG; tested on **101.1**).

## Building

Cross-compiles to `aarch64-linux-android`. The agent bundles `frida-java-bridge` (Frida 17
removed the built-in `Java` global), and `frida-core` is fetched by the `auto-download`
feature at build time (needs network + `tar`/`xz`).

```sh
# 1. build the injected agent (bundles frida-java-bridge)
cd agent && npm install && npm run build      # -> ../src/agent/bridge.js

# 2. build the FGGB binary
rustup target add aarch64-linux-android
export ANDROID_NDK_HOME=/path/to/ndk          # e.g. .../Android/Sdk/ndk/28.2.13676358
cargo install cargo-ndk
cargo ndk -t arm64-v8a build --release        # -> target/aarch64-linux-android/release/FGGB
```

## Running

```sh
adb push target/aarch64-linux-android/release/FGGB /data/local/tmp/FGGB
adb shell su -c 'chmod 755 /data/local/tmp/FGGB'
adb shell su -c 'setsid /data/local/tmp/FGGB >/data/local/tmp/fggb.log 2>&1 &'   # resident, as root
```

FGGB auto-injects `frida` into GG (and re-injects on GG restart). Then, in a GG script,
`frida.*` is available. Config via env: `FGGB_GG_PACKAGE` (override discovery),
`FGGB_POLL_SECS` (watchdog interval), `RUST_LOG`.

Milestone 3 (a Magisk module that auto-starts FGGB on boot) is planned.
