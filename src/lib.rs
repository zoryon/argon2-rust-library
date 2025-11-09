use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};  

/// Maximum password and salt lengths to prevent DoS attacks
const MAX_PASSWORD_LEN: usize = 4096;
const MAX_SALT_LEN: usize = 128;

/// Result pointer type - either valid CString pointer or null on error
type HashResult = *mut c_char;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn argon2id_hash(
    password: *const c_char, 
    salt: *const c_char
) -> HashResult {
    // Input validation
    if password.is_null() || salt.is_null() {
        return std::ptr::null_mut();
    }

    // Convert C strings to Rust with length limits
    let password_result = unsafe { CStr::from_ptr(password) }.to_str();
    let salt_result = unsafe { CStr::from_ptr(salt) }.to_str();

    if password_result.is_err() || salt_result.is_err() {
        return std::ptr::null_mut();
    }

    let password_str = password_result.unwrap();
    let salt_str = salt_result.unwrap();

    // Validate lengths
    if password_str.len() > MAX_PASSWORD_LEN || salt_str.len() > MAX_SALT_LEN {
        return std::ptr::null_mut();
    }

    let argon2 = Argon2::default();
    
    // Parse salt - assume it's provided as Base64 string from C side
    let salt_parse_result = SaltString::from_b64(salt_str);
    if salt_parse_result.is_err() {
        return std::ptr::null_mut();
    }
    let salt = salt_parse_result.unwrap();
    
    // Hash password
    let hash_result = argon2.hash_password(password_str.as_bytes(), &salt);
    if hash_result.is_err() {
        return std::ptr::null_mut();
    }
    
    let hash = hash_result.unwrap();
    
    // Convert to CString and return pointer
    let hash_string = CString::new(hash.to_string());
    if hash_string.is_err() {
        return std::ptr::null_mut();
    }
    
    hash_string.unwrap().into_raw() // Transfer ownership to C side
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn argon2id_free_hash(hash_ptr: *mut c_char) {
    if !hash_ptr.is_null() {
        // Reconstruct the CString and let it be dropped
        let _ = unsafe { CString::from_raw(hash_ptr) };
    }
}

/// Generate a cryptographically secure random salt (Base64 encoded)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn argon2id_generate_salt() -> *mut c_char {
    use rand::RngCore;
    use base64::Engine as _;
    
    // Generate 32 bytes of random data
    let mut random_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut random_bytes);
    
    // Convert to Base64
    let base64_salt = base64::engine::general_purpose::STANDARD.encode(&random_bytes);
    let cstring = CString::new(base64_salt);
    
    match cstring {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Verify a password against a hash
#[unsafe(no_mangle)]
pub unsafe extern "C" fn argon2id_verify(
    password: *const c_char,
    hash: *const c_char
) -> c_int {
    // Input validation
    if password.is_null() || hash.is_null() {
        return -1; // Error
    }
    
    let password_result = unsafe { CStr::from_ptr(password) }.to_str();
    let hash_result = unsafe { CStr::from_ptr(hash) }.to_str();
    
    if password_result.is_err() || hash_result.is_err() {
        return -1; // Error
    }
    
    let password_str = password_result.unwrap();
    let hash_str = hash_result.unwrap();
    
    // Parse the hash
    let parsed_hash = PasswordHash::new(hash_str);
    if parsed_hash.is_err() {
        return -1; // Error
    }
    
    let argon2 = Argon2::default();
    let verify_result = argon2.verify_password(password_str.as_bytes(), &parsed_hash.unwrap());
    
    match verify_result {
        Ok(_) => 1,    // Success
        Err(_) => 0,   // Invalid password
    }
}