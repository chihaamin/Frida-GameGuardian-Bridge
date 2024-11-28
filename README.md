# Frida GameGuardian Bridge (FGGB)
is a workaround to be able to run frida script from GG script.
Using Rust bindings for [Frida](https://frida.re).[![docs.rs](https://docs.rs/frida/badge.svg)](https://docs.rs/frida)

##Usage
just Download [Magisk-FGGB](https://github.com/chihaamin/FGGB-Magisk) or Download the binary in release and run it using adb or termux.

Boilerplate GG Script : 
```lua
local pid = gg.getTargetInfo().pid
local script = [[console.log(Process.id)]]

local req = gg.makeRequest(
    string.format("http://localhost:6699?pid=%d&GG=%s", pid, gg.PACKAGE),
    {
        ["content-length"] = script:len(),
        ["user-agent"] = gg.PACKAGE,
    },
    script
)
```
