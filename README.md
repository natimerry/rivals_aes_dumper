# rivals_aes_dumper

A DLL that hooks the AES encrypt/decrypt routine inside Marvel Rivals at runtime and prints every unique key to an allocated console window.

Uses [libwinexploit](https://github.com/natimerry/libwinexploit) for pattern scanning and inline hooking.

## How it works

On attach, the DLL allocates a console window and resolves the host module's PE64 header to get the image base and size, then pattern scans the `.text` section for callers of the AES encrypt/decrypt function. For each match, it walks forward to the trailing `E9` (tail-call JMP) and resolves the target address — the actual AES function. Each unique target is hooked once via `libwinexploit`, with the trampoline stored in `TRAMPOLINE_AES` so the original function continues to execute normally.

Every time the hook fires it reads the 32-byte key from `RCX`, deduplicates it via `SEEN_KEYS`, and prints a hex-encoded entry to the console.

Because the hook sits directly on the AES function rather than the asset loading path, keys are captured the moment the engine uses them — including keys for streaming assets loaded on-demand after startup. Keys are only captured when used — encrypted chunks not accessed during a session will not yield a key.

## Signature

`E8 ?? ?? ?? ?? 4C 8B C7 48 8B D6 48 8B CB 84 C0 74 ?? 48 8B 5C 24 ?? 48 8B 74 24 ?? 48 83 C4 ?? 5F E9`

## Injection

Drop the compiled DLL into the `plugins` directory as `rivals_aes_dumper.asi` using an ASI loader (e.g. [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)) configured as a proxy DLL (`winmm.dll`, `version.dll`, `dsound.dll`, etc.). The loader maps the DLL before the first level streams in, ensuring the hook is in place before any decryption occurs.

## Building

Requires the MSVC toolchain targeting `x86_64-pc-windows-msvc`. x64 only.

## Other games

This tool is written specifically for Marvel Rivals. If you've confirmed it working on another UE5 title, open a PR detailing the game, any signature differences, and your tested version.
