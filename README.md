# ue5_aes_extracter
A DLL that hooks the AES-256 decryption routine inside Unreal Engine 5 games at runtime and dumps every unique key to `C:\aes_extract_log.txt`.

Uses [libwinexploit](https://github.com/natimerry/libwinexploit) as the pattern scanning and inline hooking framework.

## How it works
On attach, the DLL resolves the host module's PE64 header to get the image base and size, then pattern scans the `.text` section for the `aes_dec1` prologue. Once found, it installs an inline hook via `libwinexploit` and stores the trampoline so the original function continues to execute normally. Every time the hook fires it reads the 32-byte key, deduplicates it, and appends a hex-encoded entry to the log file.

Because the hook sits on the decryption path rather than the asset loading path, keys are captured the moment the engine actually uses them — this includes keys for streaming assets that are loaded on-demand after the game has already started. Note that keys are only captured when used — any encrypted chunks not loaded during a session will not yield a key.

## Signature
The tool scans for the following prologue of the internal `aes_dec1` function:

```
48 8B C4              MOV RAX, RSP
48 81 EC ?? 00 00 00  SUB RSP, ??
F3 0F 6F 51 10        MOVDQU XMM2, [RCX+16]   ; key high half
F3 0F 6F 21           MOVDQU XMM4, [RCX]      ; key low half
```

The wildcard byte in `SUB RSP` accounts for varying frame sizes across builds.

If the log contains `no matches found`, the game may be using a build where the compiler emitted a different prologue, or where the AES routine has been inlined entirely (common in LTO/LTCG builds) — re-derive the signature from the binary and open a PR.

> **More signatures for other UE5 builds/versions are welcome via PR.**

## Output
Keys are written to `C:\aes_extract_log.txt`. Duplicate keys seen across multiple decryption calls are silently deduplicated. The log file is opened in append mode — delete or clear it between sessions if you want a clean capture.

> ⚠️ **Some games run with restricted write permissions and cannot write to `C:\`.** If the log file is not being created, change `LOG_FILE_PATH` in `lib.rs` to a path the game process has write access to, such as the game's own install directory or `%APPDATA%`.

## Injection

### ASI Loader (tested)
This is the recommended injection method. Drop the compiled `ue5_aes_extracter.dll` into the `plugins` directory as `ue5_aes_extracter.asi` provided by an ASI loader (e.g. [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)) renamed to a proxy DLL the game already imports (`winmm.dll`, `version.dll`, `dsound.dll`, etc.). The loader will map the DLL into the process before the first level streams in, ensuring the hook is in place before any decryption occurs.

### Manual injection (should work)
Manual injection via tools like Process Hacker, Cheat Engine's DLL injector, or a custom injector should also work, provided the DLL is injected before or early during the initial asset streaming phase. Because AES decryption is required for loading every encrypted pak chunk, keys will still be captured as long as injection happens before the relevant chunk is first decrypted.

## Tested games

| Game | Status |
|---|---|
| Marvel Rivals | Working |

If you have confirmed this working on another UE5 title, open a PR to add it to the table.

## Building
Requires the MSVC toolchain targeting `x86_64-pc-windows-msvc`. Only x64 is supported.

```powershell
cargo build --release --target x86_64-pc-windows-msvc
```

The output DLL will be at `target\x86_64-pc-windows-msvc\release\ue5_aes_extracter.dll`.

## Constraints & assumptions

- **ABI**: Assumes the Windows x64 calling convention. Builds using a non-MSVC compiler or a custom ABI may have a different parameter layout.
- **Inlining**: LTO/LTCG and highly optimised shipping builds may inline `aes_dec1` into its callers, making it unscannable by prologue. If you get no matches, check for inlining before assuming a prologue mismatch.
- **Key authenticity**: The 32 bytes read from `[RCX]` and `[RCX+16]` are assumed to be the raw AES-256 key as laid out by the UE5 key schedule. Verify against a known pak before relying on the output.
- **Scan cap**: The image scan is capped at ~15 MB. Consider using `current_module.image_size` if scan cap seems too small (this will slow down the process).
- **Thread safety**: The hook allocates and takes a mutex on every decryption call. This is not allocation-free and may cause lock contention during heavy streaming bursts. Further this probably kills frames.

## WINE
WINE compatibility should work in theory since the hook operates entirely in userspace, but this is untested. Memory permission changes and filesystem access may behave differently depending on the WINE/Proton version — syscall-based features will not function.

## Disclaimer
For personal modding and research use only. Not intended for use on titles protected by anti-cheat software or in online/multiplayer contexts. Use only on software you own and in accordance with applicable terms of service and local law.
