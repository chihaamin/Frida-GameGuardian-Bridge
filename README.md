# Frida GameGuardian Bridge (FGGB)

A localhost HTTP bridge that lets **GameGuardian (GG)** Lua scripts drive **Frida**. A GG
script POSTs a Frida JavaScript snippet + a target `pid`; FGGB attaches to that process,
loads the script, keeps the session alive, and lets you read back the script's messages
and call its `rpc.exports`.

Built on the [`frida`](https://docs.rs/frida) crate (no vendored `libfrida-core.a` /
`bind.rs` anymore). Still requires a running **`frida-server`** on the device — use
[Magisk-Frida](https://github.com/ViRb3/magisk-frida).

> **NOTE: aarch64 Android only.**

## Architecture

Frida's objects (`Frida`, `Device`, `Session`, `Script`) are `!Send`, so they live on a
single dedicated **engine thread**. The async [`axum`] HTTP server talks to it over a
command channel:

```
GG Lua ──HTTP──▶ axum handlers ──mpsc<Command>──▶ Frida engine thread ──▶ frida-server
                      ▲                                   │  owns Device + session registry
                      └──────── oneshot reply ◀───────────┘
```

Script messages (`send`, `console.log`, errors) are captured per-session into a buffer you
drain over HTTP; `rpc.exports` are callable via `POST /rpc/{id}`.

## Endpoints (default `127.0.0.1:6699`)

| Method & path | Purpose |
|---|---|
| `POST /` or `POST /inject` | Inject. Query `?pid=<pid>` (required), optional `&GG=<pkg>`, `&name=`, `&format=json`. Body = raw Frida JS. |
| `GET /messages/{id}` | Drain the session's buffered script messages (JSON array). |
| `POST /rpc/{id}` | Body `{"function":"add","args":[2,3]}` → calls `rpc.exports.add(2,3)`. |
| `GET /exports/{id}` | List the session's rpc export names. |
| `GET /sessions` | List live sessions. |
| `DELETE /session/{id}` | Unload the script + detach the session. |
| `GET /health` | `{status, frida, sessions}`. |

**Response shape for inject:** by default `text/plain` with the numeric session id in the
body (so legacy `gg.makeRequest`, which reads the body as an opaque string and checks
`code == 200`, keeps working). Send `?format=json` or `Accept: application/json` for
`{"session_id":N,"pid":P,"package":"..."}`.

### GG Lua boilerplate

```lua
local pid = gg.getTargetInfo().pid
local script = [[
  send("hello from " + Process.id);
  rpc.exports = { add: function (a, b) { return a + b; } };
]]

local resp = gg.makeRequest(
  string.format("http://localhost:6699/inject?pid=%d&GG=%s", pid, gg.PACKAGE),
  { ["content-length"] = script:len(), ["user-agent"] = gg.PACKAGE },
  script
)
-- resp.content is the session id; use it to poll messages / call rpc:
-- gg.makeRequest("http://localhost:6699/messages/" .. resp.content)
```

> A complete, commented GG script (inject → read messages → call rpc, with error
> handling) is in [`examples/fggb.lua`](examples/fggb.lua). GG Lua has **no** Frida API —
> `gg.makeRequest` (present in modern GG; v101.1 has it) is the only way to reach Frida,
> via FGGB.

## Configuration (env vars)

| Var | Default | Meaning |
|---|---|---|
| `FGGB_BIND` | `127.0.0.1:6699` | HTTP listen address |
| `FGGB_FRIDA_HOST` | `localhost` | frida-server host (TCP loopback) |
| `RUST_LOG` | `info` | tracing filter |

## Building

Cross-compiles to `aarch64-linux-android`. The `frida` dependency uses the `auto-download`
feature, so the matching **Frida core devkit is fetched at build time** (needs network +
`tar`/`xz`). The device's `frida-server` **must match that Frida major** (currently 17.x).

```sh
rustup target add aarch64-linux-android
export ANDROID_NDK_HOME=/path/to/ndk        # e.g. .../Android/Sdk/ndk/28.2.13676358
cargo install cargo-ndk                     # if not already installed
cargo ndk -t arm64-v8a build --release
# -> target/aarch64-linux-android/release/FGGB
```

> `build.rs` is an Android-only link shim: it locates the NDK's
> `libclang_rt.builtins-<arch>-android.a` and links it so frida-gum's `__clear_cache`
> resolves (rustc links with `-nodefaultlibs`). It is a no-op on non-Android targets.

## Running

```sh
adb push target/aarch64-linux-android/release/FGGB /data/local/tmp/
adb shell chmod 755 /data/local/tmp/FGGB
adb shell su -c '/data/local/tmp/frida-server &'   # 17.x, listens on 127.0.0.1:27042
adb shell su -c '/data/local/tmp/FGGB'             # listens on 127.0.0.1:6699
```

Or install [Magisk-FGGB](https://github.com/chihaamin/FGGB-Magisk) / grab a release binary.

### Quick test (from a PC via `adb forward tcp:6699 tcp:6699`)

```sh
pid=$(adb shell su -c 'pidof com.some.game')
curl -X POST "http://127.0.0.1:6699/inject?pid=$pid&format=json" \
     --data-binary 'send("hi"); rpc.exports={add:(a,b)=>a+b};'   # -> {"session_id":1,...}
curl http://127.0.0.1:6699/messages/1                            # -> [{"type":"send",...}]
curl -X POST http://127.0.0.1:6699/rpc/1 -d '{"function":"add","args":[2,3]}'  # -> 5
```
