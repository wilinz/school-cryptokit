use super::{
    decrypt_aes_128_cbc_64prefix, encrypt_aes_128_cbc_64prefix, get_decrypt_host, get_encrypt_host,
    get_ordinary_url, get_vpn_url, set_vpn_host,
};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn ffi_set_vpn_host(host: *const c_char) {
    let host_str = unsafe { CStr::from_ptr(host).to_str().unwrap() };
    set_vpn_host(host_str);
}

#[no_mangle]
pub extern "C" fn ffi_get_vpn_url(url: *const c_char) -> *mut c_char {
    let url_str = unsafe { CStr::from_ptr(url).to_str().unwrap() };
    let result = get_vpn_url(url_str);
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn ffi_get_ordinary_url(url: *const c_char) -> *mut c_char {
    let url_str = unsafe { CStr::from_ptr(url).to_str().unwrap() };
    let result = get_ordinary_url(url_str);
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn ffi_get_encrypt_host(plaintext: *const c_char) -> *mut c_char {
    let plaintext_str = unsafe { CStr::from_ptr(plaintext).to_str().unwrap() };
    let result = get_encrypt_host(plaintext_str);
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn ffi_get_decrypt_host(ciphertext: *const c_char) -> *mut c_char {
    let ciphertext_str = unsafe { CStr::from_ptr(ciphertext).to_str().unwrap() };
    let result = get_decrypt_host(ciphertext_str);
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn ffi_encrypt_aes_128_cbc_64prefix(
    plain: *const c_char,
    key: *const c_char,
) -> *mut c_char {
    let plain_str = unsafe { CStr::from_ptr(plain).to_str().unwrap() };
    let key_str = unsafe { CStr::from_ptr(key).to_str().unwrap() };
    let result = encrypt_aes_128_cbc_64prefix(plain_str, key_str);
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn ffi_decrypt_aes_128_cbc_64prefix(
    encrypted: *const c_char,
    key: *const c_char,
) -> *mut c_char {
    let encrypted_str = unsafe { CStr::from_ptr(encrypted).to_str().unwrap() };
    let key_str = unsafe { CStr::from_ptr(key).to_str().unwrap() };
    let result = decrypt_aes_128_cbc_64prefix(encrypted_str, key_str);
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn ffi_free_c_string(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        let _ = CString::from_raw(s);
    }
}
