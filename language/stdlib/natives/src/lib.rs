// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod dispatch;
pub mod hash;
pub mod primitive_helpers;
pub mod signature;
pub mod db;

extern crate libc;
use libc::size_t;

#[link(name = "eosiolib_native")]
extern {
    fn say_hello();
    fn read_action_data(msg: *mut u8, len: size_t) -> i32;
    fn action_data_size() -> i32;
    fn checktime();
}

pub fn vm_checktime() {
    unsafe {
        checktime();
    }
}

/*
uint32_t read_action_data( void* msg, uint32_t len )
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
