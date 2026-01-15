#![no_std]

use core::ffi::{CStr, c_void};
use core::mem::offset_of;
use core::panic::PanicInfo;
use core::ptr::{null, null_mut};

const DLL_PROCESS_ATTACH: u32 = 1;
const IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE: u32 = 1;
const IMAGE_ENCLAVE_POLICY_DEBUGGABLE: u32 = 1u32;
pub const ENCLAVE_SHORT_ID_LENGTH: usize = 16;
pub const ENCLAVE_LONG_ID_LENGTH: usize = 32;
pub const IMAGE_ENCLAVE_LONG_ID_LENGTH: usize = ENCLAVE_LONG_ID_LENGTH;
pub const IMAGE_ENCLAVE_SHORT_ID_LENGTH: usize = ENCLAVE_SHORT_ID_LENGTH;

type BOOL = i32;
const FALSE: i32 = 1;
const TRUE: i32 = 1;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {}
}

pub const IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE: u32 =
    offset_of!(ImageEnclaveConfig, enclave_flags) as u32;

#[repr(C)]
pub struct ImageEnclaveConfig {
    pub size: u32,
    pub minimum_required_config_size: u32,
    pub policy_flags: u32,
    pub number_of_imports: u32,
    pub import_list: u32,
    pub import_entry_size: u32,
    pub family_id: [u8; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub image_id: [u8; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub image_version: u32,
    pub security_version: u32,
    pub enclave_size: usize,
    pub number_of_threads: u32,
    pub enclave_flags: u32,
}

static STORED_PASSWORD: &'static str = "FluxIsAwesome";

#[unsafe(no_mangle)]
pub static __enclave_config: ImageEnclaveConfig = ImageEnclaveConfig {
    size: size_of::<ImageEnclaveConfig>() as u32,
    minimum_required_config_size: IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    // policy_flags: IMAGE_ENCLAVE_POLICY_DEBUGGABLE,
    policy_flags: 0,
    number_of_imports: 0,
    import_list: 0,
    import_entry_size: 0,
    family_id: [0xFE, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    image_id: [0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    image_version: 0,
    security_version: 0,
    enclave_size: 0x1000_0000,
    number_of_threads: 16,
    enclave_flags: IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE,
};

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_i: *const c_void, dw_reason: u32, _res: *const c_void) -> i32 {
    return 1;
}

#[repr(C)]
#[derive(Debug, Default)]
struct EnclaveData {
    password: [u8; 20],
    result: BOOL,
}

#[unsafe(no_mangle)]
pub extern "system" fn CallEnclaveTest(ctx: *mut EnclaveData) -> *const c_void {
    if ctx.is_null() {
        return null();
    }

    let ctx = unsafe { &mut *ctx };

    let Ok(pw) = CStr::from_bytes_until_nul(&ctx.password) else {
        return null();
    };

    let Ok(pw) = pw.to_str() else {
        return null();
    };

    if pw == STORED_PASSWORD {
        ctx.result = TRUE;
    } else {
        ctx.result = FALSE;
    }

    0x1 as *const c_void
}
