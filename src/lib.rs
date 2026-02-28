#![allow(non_snake_case)]
#![allow(unsafe_op_in_unsafe_fn)]
use libwinexploit::hooking::HookEntry;
use libwinexploit::hooking::pattern::{Pattern, PatternScanOption};
use libwinexploit::runtime::pe64_runtime::PE64Runtime;
use libwinexploit::winapi::AllocConsole;
use libwinexploit::winapi::{
    BOOL, DWORD, DisableThreadLibraryCalls, HINSTANCE, LPVOID, MessageBoxA, SetConsoleCtrlHandler,
};
use std::collections::HashSet;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{LazyLock, Mutex};
use std::thread;

static SEEN_KEYS: LazyLock<Mutex<HashSet<Vec<u8>>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

static TRAMPOLINE_AES: AtomicPtr<()> = AtomicPtr::new(null_mut());

const DLL_PROCESS_ATTACH: DWORD = 1;

static HOOKED_ADDRS: LazyLock<Mutex<HashSet<u64>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

const AES_ENC_DEC_CALLER_PATTERN: &str = "E8 ?? ?? ?? ?? 4C 8B C7 48 8B D6 48 8B CB 84 C0 74 ?? 48 8B 5C 24 ?? 48 8B 74 24 ?? 48 83 C4 ?? 5F E9";

#[cfg(debug_assertions)]
macro_rules! log {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        println!("{}", msg);
    }};
}

// The hook function whick will call and trampoline to execute the actual decrypt logic
extern "system" fn hooked_aes_fn(key_ptr: *const u8, data_ptr: *mut u8, block_count: u64) {
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

    let orig = TRAMPOLINE_AES.load(Ordering::SeqCst);
    if !orig.is_null() {
        unsafe {
            let f: extern "system" fn(*const u8, *mut u8, u64) = std::mem::transmute(orig);
            f(key_ptr, data_ptr, block_count);
        }
    }
}

unsafe fn resolve_next_jmp(addr: u64, limit: usize) -> Option<u64> {
    for i in 0..limit {
        let byte = *((addr + i as u64) as *const u8);
        if byte == 0xE9 {
            let jmp_instr = addr + i as u64;
            let rel32 = std::ptr::read_unaligned((jmp_instr + 1) as *const i32);
            let target = jmp_instr.wrapping_add(rel32 as u64).wrapping_add(5);
            return Some(target);
        }
    }
    log!(
        "[resolve_jmp] no E9 found within {} bytes of {:#x}",
        limit,
        addr
    );
    None
}

unsafe fn install_hook(addr: u64) {
    if HOOKED_ADDRS.lock().unwrap().contains(&addr) {
        log!("[install] aes_dec @ {:#x} already hooked", addr);
        return;
    }

    log!("[install] aes_dec @ {:#x}", addr);

    let mut entry = match HookEntry::new(addr as *mut u8, hooked_aes_fn as *mut u8) {
        Ok(e) => {
            TRAMPOLINE_AES.store(e.original() as *mut (), Ordering::SeqCst);
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

    let mut pattern = match Pattern::from(AES_ENC_DEC_CALLER_PATTERN) {
        Ok(p) => p,
        Err(e) => {
            log!("Pattern::from failed: {:?}", e);
            return 1;
        }
    };
    let mut vec_addr = HashSet::new();

    match pattern.scan(base, size, PatternScanOption::Begin) {
        Some(addrs) if addrs.is_empty() => {
            log!("[scan] no matches found — verify pattern against current binary");
        }
        Some(addrs) => {
            for addr in &addrs {
                log!("[scan]   {:p}", addr);
                let limit = AES_ENC_DEC_CALLER_PATTERN.split_whitespace().count();

                let call_addr = resolve_next_jmp(*addr as u64, limit).unwrap();
                vec_addr.insert(call_addr);
            }
        }
        None => {
            log!("[scan] Scan failed (wtf?)");
        }
    }

    for addr in vec_addr {
        install_hook(addr);
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

        #[cfg(debug_assertions)]
        AllocConsole();

        unsafe extern "C" fn ctrl_handler(_ctrl_type: u32) -> BOOL {
            log!("Process crashed or exited - press any key to close...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).ok();
            0
        }
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);

        std::panic::set_hook(Box::new(|info| {
            let msg = format!("{}\0", info);
            log!("PANIC: {}", info);
            let caption = b"DLL Panic\0";
            MessageBoxA(
                std::ptr::null_mut(),
                msg.as_ptr() as *const _,
                caption.as_ptr() as *const _,
                0x10,
            );
        }));

        log!("AES Dumper loaded!!");
        thread::spawn(|| unsafe { init() });
    }
    1
}
