use argon2::{Argon2, Params, Algorithm, Version, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash, Error as PasswordHashError};
use rand::rngs::OsRng;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};  

/// Maximum password and salt lengths to prevent DoS attacks
const MAX_PASSWORD_LEN: usize = 4096;
const MAX_SALT_LEN: usize = 128;

/// Argon2 limits to avoid DoS or crashes
const MIN_MEMORY_KIB: u32 = 8 * 1024;       // 8 MB
const MAX_MEMORY_KIB: u32 = 512 * 1024;     // 512 MB
const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;  // 64 MB

const MIN_ITERATIONS: u32 = 2;
const MAX_ITERATIONS: u32 = 30;
const DEFAULT_ITERATIONS: u32 = 4;

const MIN_LANES: u32 = 1;
const MAX_LANES: u32 = 64;
const DEFAULT_LANES: u32 = 2;

/// Result pointer type - either valid CString pointer or null on error
type HashResult = *mut c_char;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn argon2id_hash(
    password: *const c_char, 
    salt: *const c_char,
    memory: *const c_int, 
    iterations: *const c_int,
    parallelism: *const c_int 
) -> HashResult {
    // Input validation
    if password.is_null() || salt.is_null() {
        return std::ptr::null_mut();
    }

    // Convert C strings to Rust with length limits
    let password_cstr = unsafe { CStr::from_ptr(password) };
    let salt_cstr = unsafe { CStr::from_ptr(salt) };
    
    let password_str = match password_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let salt_str = match salt_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Validate lengths
    if password_str.len() > MAX_PASSWORD_LEN || salt_str.len() > MAX_SALT_LEN {
        return std::ptr::null_mut();
    }

    // Default values if caller passes 0 or invalid numbers
    let memory_kib = if !memory.is_null() && unsafe { *memory } >= 32 * 1024 {
        unsafe { (*memory as u32).clamp(MIN_MEMORY_KIB, MAX_MEMORY_KIB) }
    } else {
        DEFAULT_MEMORY_KIB
    };

    let time_cost = if !iterations.is_null() && unsafe { *iterations } >= 3 {
        unsafe { (*iterations as u32).clamp(MIN_ITERATIONS, MAX_ITERATIONS) }
    } else {
        DEFAULT_ITERATIONS
    };

    let lanes = if !parallelism.is_null() && unsafe { *parallelism } >= 1 {
        unsafe { (*parallelism as u32).clamp(MIN_LANES, MAX_LANES) }
    } else {
        DEFAULT_LANES
    };

    let params = Params::new(memory_kib, time_cost, lanes, None).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    // Parse salt - assume it's provided as Base64 string from C side
    let salt = match SaltString::from_b64(salt_str) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // Hash password
    let hash = match argon2.hash_password(password_str.as_bytes(), &salt) {
        Ok(h) => h,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // Convert to CString and return pointer
    match CString::new(hash.to_string()) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
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
pub extern "C" fn argon2id_generate_salt() -> *mut c_char {    
    let mut rng = OsRng;
    
    let salt = SaltString::generate(&mut rng);
    
    match CString::new(salt.as_str().to_string()) {
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
    
    let password_cstr = unsafe { CStr::from_ptr(password) };
    let hash_cstr = unsafe { CStr::from_ptr(hash) };
    
    let password_str = match password_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    let hash_str = match hash_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    // Parse the hash
    let parsed_hash = match PasswordHash::new(hash_str) {
        Ok(h) => h,
        Err(_) => return -1,
    };
    
    let argon2 = Argon2::default();
    let verify_result = argon2.verify_password(password_str.as_bytes(), &parsed_hash);

    match verify_result {
        Ok(_) => 1, // Success
        Err(PasswordHashError::Password) => 0, // Invalid password
        Err(_) => -1, // Other verification error
    }
}

/// cbindgen:ignore
#[cfg(target_os = "android")]
pub mod android {
    use super::*;
    use jni::JNIEnv;
    use jni::objects::{JClass, JString};
    use jni::sys::{jstring, jint};

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_expo_modules_argon2_Argon2Module_hash(
        mut env: JNIEnv,
        _class: JClass,
        password: JString,
        salt: JString,
        memory: jint, 
        iterations: jint,
        parallelism: jint 
    ) -> jstring {
        // Convert Java strings to Rust strings
        let password_java = match env.get_string(&password) {
            Ok(s) => s,
            Err(_) => {
                // Return empty string on error
                return env.new_string("").expect("Could not create Java string").into_raw();
            },
        };
        
        let salt_java = match env.get_string(&salt) {
            Ok(s) => s,
            Err(_) => {
                return env.new_string("").expect("Could not create Java string").into_raw();
            },
        };

        // Convert to C-compatible strings
        let password_cstr = match CString::new(password_java.to_string_lossy().into_owned()) {
            Ok(s) => s,
            Err(_) => {
                return env.new_string("").expect("Could not create Java string").into_raw();
            },
        };
        
        let salt_cstr = match CString::new(salt_java.to_string_lossy().into_owned()) {
            Ok(s) => s,
            Err(_) => {
                return env.new_string("").expect("Could not create Java string").into_raw();
            },
        };

        // Call the hash function
        let hash_ptr = unsafe {
            argon2id_hash(
                password_cstr.as_ptr(),
                salt_cstr.as_ptr(),
                &memory as *const jint as *const c_int,
                &iterations as *const jint as *const c_int,
                &parallelism as *const jint as *const c_int
            )
        };
        if hash_ptr.is_null() {
            return env.new_string("").expect("Could not create Java string").into_raw();
        }

        // Convert result back to Java string
        let hash_cstr = unsafe { CString::from_raw(hash_ptr) };
        let hash_str = match hash_cstr.into_string() {
            Ok(s) => s,
            Err(_) => {
                return env.new_string("").expect("Could not create Java string").into_raw();
            },
        };

        env.new_string(hash_str).expect("Could not create Java string").into_raw()
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_expo_modules_argon2_Argon2Module_generateSalt(
        env: JNIEnv,
        _class: JClass,
    ) -> jstring {
        let salt_ptr = argon2id_generate_salt();
        if salt_ptr.is_null() {
            return env.new_string("").expect("Could not create Java string").into_raw();
        }

        let salt_cstr = unsafe { CString::from_raw(salt_ptr) };
        let salt_str = match salt_cstr.into_string() {
            Ok(s) => s,
            Err(_) => {
                return env.new_string("").expect("Could not create Java string").into_raw();
            },
        };

        env.new_string(salt_str).expect("Could not create Java string").into_raw()
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_expo_modules_argon2_Argon2Module_verify(
        mut env: JNIEnv,
        _class: JClass,
        password: JString,
        hash: JString
    ) -> jni::sys::jint {
        // Convert Java strings to Rust strings
        let password_java = match env.get_string(&password) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        
        let hash_java = match env.get_string(&hash) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        // Convert to C-compatible strings
        let password_cstr = match CString::new(password_java.to_string_lossy().into_owned()) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        
        let hash_cstr = match CString::new(hash_java.to_string_lossy().into_owned()) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        // Call the verify function
        let result = unsafe { argon2id_verify(password_cstr.as_ptr(), hash_cstr.as_ptr()) };
        result
    }
}