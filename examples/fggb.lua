--[[
  FGGB example — use Frida from a GameGuardian script.

  Requirements:
    * FGGB running on the device (as root): it injects the `frida` global into GG.
    * A target selected in GG (GG's process list) — frida.* instruments THAT process.
    * The target must be Frida-attachable (games with anti-Frida protection may block it).

  There is no HTTP and no gg.makeRequest here — `frida` is a global inside GG's Lua,
  installed by FGGB, exactly like `gg`.
]]

-- Guard: is the FGGB bridge present?
if type(frida) ~= "table" then
  gg.alert("`frida` is not available.\nStart FGGB on the device (as root) first.")
  return
end

-- Which process is GG targeting?
local tgt = frida.target()          -- "target pid <pid>" or "no target selected..."
if tgt:find("no target") then
  gg.alert(tgt .. "\n\nSelect a process as GG's target, then run this again.")
  return
end

-- Simple menu.
local choice = gg.choice({
  "Target info + modules",
  "Find & read a module (libil2cpp.so)",
  "Hook libc open() and watch calls",
  "Run custom Frida JS",
}, nil, tgt)
if choice == nil then return end

------------------------------------------------------------------ 1. modules ----
if choice == 1 then
  gg.alert(tgt .. "\n\n" .. frida.modules())            -- name  base  size (all modules)

------------------------------------------------------- 2. find + read a module ----
elseif choice == 2 then
  local base = frida.base("libil2cpp.so")
  if base == "not found" then
    gg.alert("libil2cpp.so not found in the target (not a Unity/il2cpp game?)")
    return
  end
  local hdr = frida.read(base, 16)                       -- first 16 bytes (ELF header)
  gg.alert("libil2cpp.so base: " .. base .. "\nheader: " .. hdr)

------------------------------------------------------------- 3. hook open() -------
elseif choice == 3 then
  local addr = frida.export("libc.so", "open")
  if addr == "not found" then gg.alert("open() not found"); return end
  local resp = frida.hook(addr)                          -- "[session N] hook installed..."
  local sid = resp:match("%[session (%d+)%]")
  gg.toast("Hook installed (session " .. tostring(sid) .. "). Play for a few seconds...")
  gg.sleep(4000)
  gg.alert("open() calls:\n" .. frida.pull(sid))         -- drain captured hits
  frida.kill(sid)                                        -- clean up

------------------------------------------------------------- 4. custom JS ---------
elseif choice == 4 then
  -- Arbitrary Frida JS runs in the target (core Gum API). send(...) is returned.
  local out = frida.run([[
    var n = Process.enumerateModules().length;
    var il = Process.findModuleByName("libil2cpp.so");
    send("target pid " + Process.id + ", " + n + " modules, il2cpp=" + (il ? il.base : "no"));
  ]])
  gg.alert(out)
end

--[[
  Cheatsheet (also: gg.alert(frida.help())):
    frida.target()                 frida.modules([filter])
    frida.base(module)             frida.export(module, symbol)
    frida.read(addr, len)          frida.write(addr, "AA BB ..")
    frida.scan("AA ?? CC")         frida.hook(addr) -> [session N]
    frida.run(js) -> [session N]   frida.pull(sid)   frida.kill(sid)
    frida.runpid("pid|js")         frida.version()   frida.help()
]]
