#![allow(non_snake_case)]
#![allow(unsafe_op_in_unsafe_fn)]
use libwinexploit::hooking::pattern::{Pattern, PatternScanOption};
use libwinexploit::hooking::HookEntry;
use libwinexploit::runtime::pe64_runtime::PE64Runtime;
use libwinexploit::winapi::{DisableThreadLibraryCalls, BOOL, DWORD, HINSTANCE, LPVOID};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{LazyLock, Mutex};
use std::thread;

const LOG_FILE_PATH: &str = "C:\\aes_extract_log.txt";

static LOG_FILE: LazyLock<Mutex<std::fs::File>> = LazyLock::new(|| {
    Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(LOG_FILE_PATH)
            .expect("failed to open log"),
    )
});

static SEEN_KEYS: LazyLock<Mutex<HashSet<Vec<u8>>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

static ORIGINAL_AES_DEC: AtomicPtr<()> = AtomicPtr::new(null_mut());

const DLL_PROCESS_ATTACH: DWORD = 1;

// ─────────────────────────────────────────────────────────────
// Prologue signature for aes_dec1:
//   48 8B C4              MOV RAX, RSP
//   48 81 EC ?? 00 00 00  SUB RSP, ??        <- frame size
//   F3 0F 6F 51 10        MOVDQU XMM2, [RCX+16]   <- key high half
//   F3 0F 6F 21           MOVDQU XMM4, [RCX]      <- key low half
// ─────────────────────────────────────────────────────────────
const AES_DEC1_PATTERN: &str = "48 8B C4 48 81 EC ?? 00 00 00 F3 0F 6F 51 10 F3 0F 6F 21";

macro_rules! log {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        if let Ok(mut f) = LOG_FILE.lock() {
            let _ = writeln!(f, "{}", msg);
        }
    }};
}

// The hook function whick will call and trampoline to execute the actual decrypt logic
extern "system" fn hook_aes_dec(key_ptr: *const u8, data_ptr: *mut u8, block_count: u64) {
    if !key_ptr.is_null() {
        unsafe {
            let key = std::slice::from_raw_parts(key_ptr, 32);

            if key.iter().any(|&b| b != 0) {
                let mut seen = SEEN_KEYS.lock().unwrap();
                if seen.insert(key.to_vec()) {
                    let mut hex = String::with_capacity(2 + 64);
                    hex.push_str("0x");
                    for b in key {
                        use std::fmt::Write;
                        write!(&mut hex, "{:02x}", b).unwrap();
                    }

                    log!("[AES-256 KEY] {}", hex);
                }
            }
        }
    }

    let orig = ORIGINAL_AES_DEC.load(Ordering::SeqCst);
    if !orig.is_null() {
        unsafe {
            let f: extern "system" fn(*const u8, *mut u8, u64) = std::mem::transmute(orig);
            f(key_ptr, data_ptr, block_count);
        }
    }
}

unsafe fn install_hook(addr: u64) {
    log!("[install] aes_dec @ {:#x}", addr);

    let mut entry = match HookEntry::new(addr as *mut u8, hook_aes_dec as *mut u8) {
        Ok(e) => {
            ORIGINAL_AES_DEC.store(e.original() as *mut (), Ordering::SeqCst);
            e
        }
        Err(e) => {
            log!("[install] HookEntry failed: {:?}", e);
            return;
        }
    };

    match entry.toggle() {
        Ok(_) => log!("[install] Hook is active"),
        Err(e) => log!("[install] Failed to install hook: {:?}", e),
    }
}

unsafe fn init() -> BOOL {
    let module = match PE64Runtime::from_current_module() {
        Ok(m) => m,
        Err(e) => {
            log!("PE64Runtime failed: {:?}", e);
            return 1;
        }
    };

    let base = module.module_base as *const u8;
    let size = module.image_size.min(15826958) as usize;
    log!("base={:p} size={:#x}", base, size);

    let mut pattern = match Pattern::from(AES_DEC1_PATTERN) {
        Ok(p) => p,
        Err(e) => {
            log!("Pattern::from failed: {:?}", e);
            return 1;
        }
    };

    match pattern.scan(base, size, PatternScanOption::Begin) {
        Some(addrs) if addrs.is_empty() => {
            log!("[scan] no matches found — verify pattern against current binary");
        }
        Some(addrs) => {
            for addr in &addrs {
                log!("[scan]   {:p}", addr);
            }
            // Only hook the first match — pattern should be unique
            if addrs.len() > 1 {
                log!(
                    "[scan] WARNING: multiple matches, pattern may not be unique — hooking first only"
                );
            }
            install_hook(*addrs.first().unwrap() as u64);
        }
        None => {
            log!("[scan] Scan failed (wtf?)");
        }
    }

    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: DWORD,
    _lpv_reserved: LPVOID,
) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(hinst_dll as *mut _);

        log!("AES Dumper loaded!!");
        thread::spawn(|| unsafe { init() });
    }
    1
}
