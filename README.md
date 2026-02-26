# ue5_aes_extracter

A DLL that hooks the AES encrypt/decrypt routine inside Unreal Engine 5 games at runtime and dumps every unique key to `C:\aes_extract_log.txt`.

Uses [libwinexploit](https://github.com/natimerry/libwinexploit) for pattern scanning and inline hooking.

## How it works

On attach, the DLL resolves the host module's PE64 header to get the image base and size, then pattern scans the `.text` section for callers of the AES encrypt/decrypt function. For each match, it walks forward to the trailing `E9` (tail-call JMP) and resolves the target address — the actual AES function. Each unique target is hooked once via `libwinexploit`, with the trampoline stored in `TRAMPOLINE_AES` so the original function continues to execute normally.

Every time the hook fires it reads the 32-byte key from `RCX`, deduplicates it via `SEEN_KEYS`, and appends a hex-encoded entry to the log file.

Because the hook sits directly on the AES function rather than the asset loading path, keys are captured the moment the engine uses them — including keys for streaming assets loaded on-demand after startup. Keys are only captured when used — encrypted chunks not accessed during a session will not yield a key.

## Signature

The tool scans for callers of the AES function using the following pattern:
`E8 ?? ?? ?? ?? 4C 8B C7 48 8B D6 48 8B CB 84 C0 74 ?? 48 8B 5C 24 ?? 48 8B 74 24 ?? 48 83 C4 ?? 5F E9`

Multiple callers are handled — each unique resolved address is hooked independently.

## Output

Keys are written to `C:\aes_extract_log.txt` in append mode. Duplicates are silently deduplicated. Delete or clear the file between sessions for a clean capture.

> ⚠️ **Some games run with restricted write permissions.** If the log file is not being created, change `LOG_FILE_PATH` in `lib.rs` to a path the game process can write to (game install directory, `%APPDATA%`, etc.)


## Injection

### ASI Loader (recommended)

Drop the compiled DLL into the `plugins` directory as `ue5_aes_extracter.asi` using an ASI loader (e.g. [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)) configured as a proxy DLL (`winmm.dll`, `version.dll`, `dsound.dll`, etc.). The loader maps the DLL before the first level streams in, ensuring the hook is in place before any decryption occurs.

### Manual injection

Manual injection via Process Hacker, Cheat Engine's DLL injector, or a custom injector works provided the DLL is injected before the relevant pak chunks are first decrypted.

## Tested games

| Game | Status |
|---|---|
| Marvel Rivals | Working |

If you have confirmed this working on another UE5 title, open a PR to add it to the table.

## Building

Requires the MSVC toolchain targeting `x86_64-pc-windows-msvc`. x64 only.
