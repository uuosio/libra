// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::dispatch::{CostedReturnType, NativeReturnType, Result, StackAccessor};
use bitcoin_hashes::{hash160, sha256, Hash};
use std::borrow::Borrow;
use tiny_keccak::Keccak;
use types::byte_array::ByteArray;

extern crate libc;
use libc::size_t;

#[link(name = "eosiolib_native")]
extern {
    fn say_hello();
    fn read_action_data(msg: *mut u8, len: size_t) -> i32;
    fn action_data_size() -> i32;
    fn checktime();
    fn prints_l( msg: *const u8, len: size_t);
}

pub fn vm_checktime() {
    unsafe {
        checktime();
    }
}

pub fn vm_print(msg: &[u8]) {
    unsafe {
        prints_l(msg.as_ptr(), msg.len());
    }
}

pub fn native_print<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    let hash_arg = match accessor.get_byte_array() {
        Ok(hash_arg)  => hash_arg,
        Err(e) => return Err(e),
    };
//    let hash_arg = accessor.get_byte_array().unwrap().as_bytes();
    /*
    hash_arg.as_ptr();
    hash_arg.len();
    */
    vm_print(hash_arg.as_bytes());
//    println!("{}", hash_arg);
    Ok(CostedReturnType::new(0, NativeReturnType::Bool(true)))
}
