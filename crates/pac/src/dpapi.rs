//! Windows DPAPI sealer in `LOCAL_MACHINE` scope.
//!
//! `CryptProtectData` / `CryptUnprotectData` with `CRYPTPROTECT_LOCAL_MACHINE`
//! bind the sealed MAT to the host (any process on the machine can unseal it,
//! which is required: the machine boot context seals it and the user logon
//! context must read it) while preventing it from being lifted to another host.
//!
//! `unsafe` is confined to the two documented DPAPI calls.

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData, CryptUnprotectData,
};

use crate::error::PacError;
use crate::store::Sealer;

/// DPAPI machine-scope sealer.
#[derive(Debug, Default, Clone, Copy)]
pub struct DpapiSealer;

/// Run a DPAPI protect/unprotect call and copy the result into an owned `Vec`,
/// freeing the API-allocated output buffer. `protect` selects the direction.
fn dpapi_call(input: &[u8], protect: bool) -> Result<Vec<u8>, PacError> {
    // The input blob's pbData is not mutated by DPAPI; the cast to *mut is the
    // API's (non-const-correct) signature.
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(input.len()).map_err(|_| err(protect, 0))?,
        pbData: input.as_ptr().cast_mut(),
    };
    let mut out = CRYPT_INTEGER_BLOB::default();

    // SAFETY: `in_blob` points at `input` for the duration of the call; `out` is
    // an owned local that DPAPI fills with a LocalAlloc'd buffer we free below.
    let in_ptr = &raw const in_blob;
    let out_ptr = &raw mut out;
    let result = unsafe {
        if protect {
            CryptProtectData(
                in_ptr,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                out_ptr,
            )
        } else {
            CryptUnprotectData(in_ptr, None, None, None, None, 0, out_ptr)
        }
    };
    result.map_err(|e| err(protect, e.code().0))?;

    // Copy out then free the DPAPI buffer.
    let len = out.cbData as usize;
    // SAFETY: on success DPAPI set `out.pbData`/`cbData` to a valid buffer.
    let copied = if out.pbData.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { core::slice::from_raw_parts(out.pbData, len).to_vec() }
    };
    if !out.pbData.is_null() {
        // SAFETY: `out.pbData` was allocated by DPAPI with LocalAlloc; free once.
        let _ = unsafe { LocalFree(Some(HLOCAL(out.pbData.cast()))) };
    }
    Ok(copied)
}

fn err(protect: bool, detail: i32) -> PacError {
    if protect {
        PacError::Seal { detail }
    } else {
        PacError::Unseal { detail }
    }
}

impl Sealer for DpapiSealer {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, PacError> {
        dpapi_call(plaintext, true)
    }
    fn unseal(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PacError> {
        dpapi_call(ciphertext, false)
    }
}
