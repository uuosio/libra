// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod dispatch;
pub mod hash;
pub mod primitive_helpers;
pub mod signature;
pub mod db;
pub mod debug;
pub mod vm_api;

extern crate libc;
use libc::size_t;

#[link(name = "eosiolib_native")]
extern {
    fn say_hello();
    fn read_action_data(msg: *mut u8, len: size_t) -> i32;
    fn action_data_size() -> i32;
    fn checktime();
    fn is_account( name: u64 ) -> bool;
    fn current_receiver() -> u64;

    fn db_store_i64(scope: u64, table: u64, payer: u64, id: u64,  data: *const u8, len: size_t);
    fn db_update_i64(iterator: i32, payer: u64, data: *const u8, len: size_t);
    fn db_remove_i64(iterator: i32);
    fn db_get_i64(iterator: i32, data: *mut u8, len: size_t) -> i32;
    fn db_next_i64(iterator: i32, primary: *mut u64) -> i32;
    fn db_previous_i64(iterator: i32, primary: *mut u64) -> i32;
    fn db_find_i64(code: u64, scope: u64, table: u64, id: u64) -> i32;
    fn db_lowerbound_i64(code: u64, scope: u64, table: u64, id: u64) -> i32;
    fn db_upperbound_i64(code: u64, scope: u64, table: u64, id: u64) -> i32;
    fn db_end_i64(code: u64, scope: u64, table: u64) -> i32;

    fn db_store_i256( scope: u64, table: u64, payer: u64, id: *const u8, size: size_t, buffer: *const u8, buffer_size: size_t ) -> i32;
    fn db_update_i256( iterator: i32, payer: u64, buffer: *const u8, buffer_size: size_t );
    fn db_remove_i256( iterator: i32 );
    fn db_get_i256( iterator: i32, buffer: *mut u8, buffer_size: size_t ) -> size_t;
    fn db_find_i256( code: u64, scope: u64, table: u64, id : *const u8, size: size_t ) -> i32;

    fn set_last_error(error: *const u8, len: size_t);
    fn clear_last_error();
}

pub fn vm_set_last_error(error: &[u8]) {
    unsafe {
        set_last_error(error.as_ptr(), error.len());
    }
}

pub fn vm_clear_last_error() {
    unsafe {
        clear_last_error();
    }
}

pub fn vm_checktime() {
    unsafe {
        checktime();
    }
}

pub fn vm_current_receiver() ->u64 {
    unsafe {
        current_receiver()
    }
}

pub fn vm_is_account(name: u64) ->bool {
    unsafe {
        is_account(name)
    }
}

pub fn vm_db_store_i64(scope: u64, table: u64, payer: u64, id: u64,  data: &[u8]) {
    return unsafe {
        db_store_i64(scope, table, payer, id,  data.as_ptr(), data.len())
    }
}

pub fn vm_db_update_i64(iterator: i32, payer: u64, data: &[u8]) {
    unsafe {
        db_update_i64(iterator, payer, data.as_ptr(), data.len());
    }
}

pub fn vm_db_remove_i64(iterator: i32) {
    unsafe {
        db_remove_i64(iterator);
    }
}

pub fn vm_db_get_i64(iterator: i32, data: &mut [u8]) {
    unsafe {
        db_get_i64(iterator, data.as_mut_ptr(), data.len());
    }
}

pub fn vm_db_next_i64(iterator: i32, primary: &mut u64) -> i32 {
    unsafe {
        db_next_i64(iterator, primary as *mut u64)
    }
}

pub fn vm_db_previous_i64(iterator: i32, primary: &mut u64) -> i32 {
    unsafe {
        db_previous_i64(iterator, primary as *mut u64)
    }
}

pub fn vm_db_find_i64(code: u64, scope: u64, table: u64, id: u64) -> i32 {
    unsafe {
        db_find_i64(code, scope, table, id)
    }
}

pub fn vm_db_lowerbound_i64(code: u64, scope: u64, table: u64, id: u64) -> i32 {
    unsafe {
        db_lowerbound_i64(code, scope, table, id)
    }
}

pub fn vm_db_upperbound_i64(code: u64, scope: u64, table: u64, id: u64) -> i32 {
    unsafe {
        db_upperbound_i64(code, scope, table, id)
    }
}

pub fn vm_db_end_i64(code: u64, scope: u64, table: u64) -> i32 {
    unsafe {
        db_end_i64(code, scope, table)
    }
}

pub fn vm_store_i256(id: &[u8], buffer: &[u8]) -> Option<Vec<u8>> {
    let code: u64;
    let scope: u64;
    let table: u64;
    let payer: u64;

    code = vm_current_receiver();
    scope = code;
    table = code;
    payer = code;

    unsafe {
        assert_eq!(id.len(), 32);
        assert_eq!(code, vm_current_receiver());
        let itr = db_find_i256(code, scope, table, id.as_ptr(), id.len());
        if itr >= 0 {
            let value = vm_get_i256(id);
            db_update_i256(itr, payer, buffer.as_ptr(), buffer.len());
            return value;
        } else {
            db_store_i256(scope, table, payer, id.as_ptr(), id.len(), buffer.as_ptr(), buffer.len());
            return None;
        }
    }
}

pub fn vm_get_i256(id: &[u8]) -> Option<Vec<u8>> {
    let code: u64;
    let scope: u64;
    let table: u64;
    code = vm_current_receiver();
    scope = code;
    table = code;

    unsafe {
        let itr = db_find_i256(code, scope, table, id.as_ptr(), id.len());
        if itr < 0 {
            return None;
        }
        let size = db_get_i256(itr, (&mut []).as_mut_ptr(), 0);
        if size == 0 {
            return None;
        }
        let mut buffer: Vec<u8> = vec![0;size];
        db_get_i256(itr, (&mut buffer).as_mut_ptr(), size);
        return Some(buffer);
    //    Ok([])
    }
}

pub fn vm_remove_i256(id: &[u8]) -> Option<Vec<u8>> {
    let code: u64;
    let scope: u64;
    let table: u64;
    let payer: u64;

    code = vm_current_receiver();
    scope = code;
    table = code;
    payer = code;

    unsafe {
        assert_eq!(id.len(), 32);
        assert_eq!(code, vm_current_receiver());
        let itr = db_find_i256(code, scope, table, id.as_ptr(), id.len());
        if itr >= 0 {
            let value = vm_get_i256(id);
            db_remove_i256(itr);
            return value;
        } else {
            return None;
        }
    }
}

/*
    fn db_store_i256( code: u64, scope: u64, table: u64, payer: u64, id: *const u8, size: size_t, buffer: *const u8, buffer_size: size_t ) -> i32;
    fn db_update_i256( iterator: i32, payer: u64, buffer: *const u8, buffer_size: size_t );
    fn db_remove_i256( iterator: i32 );
    fn db_get_i256( iterator: i32, buffer: *mut u8, buffer_size: size_t ) -> size_t;
    fn db_find_i256( code: u64, scope: u64, table: u64, id : *const u8, size: size_t ) -> i32;
*/

/*
uint32_t read_action_data( void* msg, len: size_t )
uint32_t action_data_size()
void require_recipient( account_name name )
void require_auth( account_name name )
bool has_auth( account_name name )
void require_auth2( account_name name, permission_name permission )
bool is_account( account_name name )
void send_inline(char *serialized_action, size_t size)
void send_context_free_inline(char *serialized_action, size_t size)
uint64_t  publication_time()
*/
