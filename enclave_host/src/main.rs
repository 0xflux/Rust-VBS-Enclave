use std::{ffi::c_void, process::exit, ptr::null_mut};

use windows_sys::{
    Win32::{
        Foundation::{FALSE, GetLastError, HANDLE, HMODULE, SetLastError, TRUE},
        System::{
            Diagnostics::Debug::{GetThreadErrorMode, SEM_FAILCRITICALERRORS, SetThreadErrorMode},
            LibraryLoader::GetProcAddress,
            Threading::GetCurrentProcess,
        },
    },
    core::{BOOL, PCWSTR},
    s, w,
};

const ENCLAVE_TYPE_VBS: u32 = 0x00000010;
const ENCLAVE_VBS_FLAG_DEBUG: u32 = 0x00000001;

type PENCLAVE_ROUTINE = unsafe extern "system" fn(*mut c_void) -> *mut c_void;

#[link(name = "OneCore")]
unsafe extern "system" {
    fn CallEnclave(
        lpRoutine: *const c_void,
        lpParameter: *mut c_void,
        fWaitForThread: BOOL,
        lpReturnValue: *mut *mut c_void,
    ) -> BOOL;

    fn IsEnclaveTypeSupported(flenclavetype: u32) -> BOOL;

    fn CreateEnclave(
        hprocess: *mut c_void,
        lpaddress: *const c_void,
        dwsize: usize,
        dwinitialcommitment: usize,
        flenclavetype: u32,
        lpenclaveinformation: *const c_void,
        dwinfolength: u32,
        lpenclaveerror: *mut u32,
    ) -> *mut c_void;

    fn LoadEnclaveImageW(lpenclaveaddress: *const c_void, lpimagename: PCWSTR) -> BOOL;

    fn InitializeEnclave(
        hprocess: HANDLE,
        lpaddress: *const c_void,
        lpenclaveinformation: *const c_void,
        dwinfolength: u32,
        lpenclaveerror: *mut u32,
    ) -> BOOL;

    fn TerminateEnclave(lpaddress: *const c_void, fwait: BOOL) -> BOOL;

    fn DeleteEnclave(lpaddress: *const c_void) -> BOOL;
}

fn main() {
    println!("[i] Starting enclave test..");

    if let Err(e) = run_enclave() {
        println!("{e:?}");
        exit(0);
    };
}

#[derive(Debug)]
enum ProgramError {
    VbsNotSupported,
    FailedToLoadImage(u32),
    FailedToInitEnclave(u32),
    FailedToFindFunction,
    FailedToCallFunction,
}

#[repr(C)]
#[derive(Default)]
struct EnclaveCreateInfoVbs {
    flags: u32,
    owner_id: [u8; 32],
}

#[repr(C)]
#[derive(Default)]
struct EnclaveInitInfoVbs {
    length: u32,
    thread_count: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
struct EnclaveData {
    password: [u8; 20],
    result: bool,
}

// type CallEnclaveTest = unsafe extern "system" fn(ctx: *const c_void) -> *const c_void;

fn run_enclave() -> Result<(), ProgramError> {
    unsafe {
        if IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS) == FALSE {
            return Err(ProgramError::VbsNotSupported);
        };

        let mut create_info = EnclaveCreateInfoVbs {
            // flags: ENCLAVE_VBS_FLAG_DEBUG,
            flags: 0,
            owner_id: Default::default(),
        };

        create_info.owner_id[..8]
            .copy_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x41, 0x31, 0x21, 0x11]);

        let p_enclave = CreateEnclave(
            GetCurrentProcess(),
            null_mut(),
            0x10000000,
            0, // not used for VBS
            ENCLAVE_TYPE_VBS,
            &create_info as *const _ as *const c_void,
            size_of_val(&create_info) as u32,
            null_mut(),
        );

        println!("[i] Enclave address: {p_enclave:p}");

        // Load enclave module with SEM_FAILCRITICALERRORS enabled to suppress
        // the error message dialog.
        let previous_mode = GetThreadErrorMode();
        SetThreadErrorMode(previous_mode | SEM_FAILCRITICALERRORS, null_mut());

        //
        // Load the image into the secure enclave
        //
        if LoadEnclaveImageW(p_enclave, w!("vbs_enclave.dll")) == FALSE {
            let gle = GetLastError();
            println!("[-] Failed to load enclave image, error: {gle:#X}");
            terminate_enclave(p_enclave);

            return Err(ProgramError::FailedToLoadImage(gle));
        }

        println!("[i] Image loaded into enclave..");

        //
        // Initialise the enclave with one thread; once initialised, no more DLLs can be loaded in..
        //
        let mut init_info = EnclaveInitInfoVbs::default();
        init_info.length = size_of::<EnclaveInitInfoVbs>() as u32;
        init_info.thread_count = 1;

        if InitializeEnclave(
            GetCurrentProcess(),
            p_enclave,
            &init_info as *const _ as *const _,
            init_info.length,
            null_mut(),
        ) == FALSE
        {
            let gle = GetLastError();
            println!("[-] Failed to initialise enclave image, error: {gle:#X}");
            terminate_enclave(p_enclave);

            return Err(ProgramError::FailedToInitEnclave(gle));
        }

        //
        // Locate the function in the enclave..
        //

        let Some(proc) = GetProcAddress(p_enclave as HMODULE, s!("CallEnclaveTest")) else {
            let gle = GetLastError();
            println!("[-] GetProcAddress failed: {gle:#X}");
            terminate_enclave(p_enclave);
            return Err(ProgramError::FailedToFindFunction);
        };

        let mut input = EnclaveData::default();
        input.result = false;
        let correct_password = "FluxIsAwesome".as_bytes();
        let incorrect_password = "Test".as_bytes();
        input.password[..correct_password.len()].copy_from_slice(correct_password);

        let mut output: *mut bool = null_mut();

        if CallEnclave(
            proc as *const c_void,
            &mut input as *mut _ as *mut c_void,
            TRUE,
            &mut output as *mut _ as *mut *mut _,
        ) == FALSE
        {
            let gle = GetLastError();
            println!("[-] Failed to call function CallEnclaveTest, error: {gle:#X}");
            terminate_enclave(p_enclave);

            return Err(ProgramError::FailedToCallFunction);
        };

        if input.result == true {
            println!("[+] Congrats you guessed the password!");
        } else {
            println!("[-] Sorry that password was incorrect!");
        }

        //
        // Terminate the enclave
        //
        terminate_enclave(p_enclave);
    }

    Ok(())
}

fn terminate_enclave(p_enclave: *const c_void) {
    unsafe {
        // fWait: TRUE if TerminateEnclave should not return until all of
        // the threads in the enclave end execution. FALSE if TerminateEnclave should return immediately.
        TerminateEnclave(p_enclave, TRUE);
        DeleteEnclave(p_enclave);
    }
}
