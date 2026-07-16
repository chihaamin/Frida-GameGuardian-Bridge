# FGGB `frida.*` API reference

FGGB injects a `frida` global into GameGuardian's Lua. These functions instrument **GG's
current target** — the process you selected in GG (`gg.getTargetInfo().pid`) — by having
the FGGB controller attach Frida to it, run the operation, and return the result to Lua.

Select a target in GG **before** calling target functions, or they return
`"no target selected in GameGuardian"`.

## Model

- Every call is **synchronous** from Lua's point of view: it blocks the GG script until FGGB
  replies, then returns a string.
- **One-shot** ops (`modules`, `base`, `export`, `read`, `write`, `scan`) attach to the
  target, run, and detach immediately — nothing persists.
- **Session** ops (`run`, `hook`) keep an agent loaded in the target and return a header
  `"[session N] ..."`. Later `send()`s / hook hits accumulate; read them with
  `frida.pull(N)`. Free the session with `frida.kill(N)`.
- Addresses are strings (`"0x7b12ac0000"`), as returned by other calls and accepted by GG.

## Target introspection

### `frida.target() -> string`
The current target pid, e.g. `"target pid 16066"`.

### `frida.modules([filter]) -> string`
Loaded modules in the target, one per line as `name  base  size`. Optional case-insensitive
substring `filter`.
```lua
gg.alert(frida.modules("il2cpp"))   -- libil2cpp.so  0x7b...  0x1a4c000
```

### `frida.base(module) -> string`
Base address of `module`, or `"not found"`.
```lua
local base = frida.base("libil2cpp.so")
```

### `frida.export(module, symbol) -> string`
Address of an exported symbol, or `"not found"`.
```lua
local open = frida.export("libc.so", "open")
```

## Memory

### `frida.read(addr, len) -> string`
`len` bytes at `addr` as space-separated hex.
```lua
gg.alert(frida.read(frida.base("libil2cpp.so"), 16))   -- "7f 45 4c 46 ..."
```

### `frida.write(addr, "AA BB ..") -> string`
Write space-separated hex bytes at `addr`.
```lua
frida.write("0x7b12ac0010", "90 90 90 90")
```

### `frida.scan(pattern) -> string`
Addresses (max 100) whose bytes match a Frida byte pattern; `??` is a wildcard byte.
```lua
gg.alert(frida.scan("48 8b 05 ?? ?? ?? ??"))
```

## Hooks & arbitrary code

### `frida.hook(addr) -> string`
Install an `Interceptor` at `addr` that logs each call's first 4 args. Returns
`"[session N] ..."`. Read hits with `frida.pull(N)`.
```lua
local sid = frida.hook(frida.export("libc.so", "open")):match("%[session (%d+)%]")
-- play the game, then:
gg.alert(frida.pull(sid))     -- "hit args 0x.. .. .. .."
```

### `frida.run(js) -> string`
Run arbitrary Frida JavaScript in the target (full core Gum API). The script's top-level
`send(...)` output is returned; the session stays loaded (for hooks). Returns
`"[session N]\n<output>"`.
```lua
local out = frida.run([[
  var p = Module.findExportByName("libil2cpp.so", "il2cpp_string_new");
  Interceptor.attach(p, { onEnter:function(a){ send("string_new " + a[0].readUtf8String()); }});
  send("hooked in " + Process.id);
]])
```

### `frida.pull(sid) -> string`
Drain buffered events (hook hits, `send()`s) from session `sid`, newline-separated. Call
repeatedly to poll.

### `frida.kill(sid) -> string`
Unload the script and detach session `sid`.

## Escape hatch & misc

### `frida.runpid("pid|js") -> string`
Run `js` in an **explicit** pid (ignores GG's target). Useful for a process GG isn't on.
```lua
gg.alert(frida.runpid("1845|send('hi from ' + Process.id)"))
```

### `frida.version()` / `frida.help()`
Frida version string / a printed cheatsheet of the API.

## Notes & caveats

- **Attachable targets only.** FGGB injects an agent into the target. Games with anti-Frida
  protection (e.g. **Grim Soul**) block late attach — calls return
  `"error: attach failed ..."`. GG's own memory editing still works on those; Frida hooking
  does not (until spawn-time instrumentation / a bypass is added).
- **Core Gum only in the target.** `Java` / `ObjC` bridges are not loaded in the injected
  target code. Native hooking (Interceptor/Memory/Module) works.
- **One-shot latency.** Each one-shot op attaches + detaches (~0.5–1 s). For many operations,
  prefer a single `frida.run(js)` that does everything and `send()`s a summary.
- **Errors** come back as readable strings (`"error: ..."`, `"target error: ..."`,
  `"not found"`), never as Lua exceptions.
