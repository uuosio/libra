// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::dispatch::{CostedReturnType, NativeReturnType, Result, StackAccessor};
use bitcoin_hashes::{hash160, sha256, Hash};
use std::borrow::Borrow;
use tiny_keccak::Keccak;
use types::byte_array::ByteArray;

extern crate libc;
use libc::size_t;

use failure::*;

#[link(name = "eosiolib_native")]
extern {
    fn say_hello();

    fn read_action_data(msg: *mut u8, len: size_t) -> i32;
    fn action_data_size() -> size_t;
    fn require_recipient(name: u64);
    fn require_auth(name: u64);
    fn has_auth(name: u64) -> bool;
    fn require_auth2(name: u64, permission:u64);
    fn is_account(name: u64) -> bool;
    fn send_inline(serialized_action: *const u8, size: size_t);
    fn send_context_free_inline(serialized_action: *const u8, size: size_t);
    fn publication_time() -> u64;
    fn current_receiver() -> u64;
    fn call_contract(contract: u64, func_name: u64, arg1: u64, arg2: u64, arg3: u64, extra_args: *const u8, size1: size_t);
}

pub fn native_require_auth<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    let name = match accessor.get_u64() {
        Ok(name)  => name,
        Err(e) => return Err(e),
    };
    let b = unsafe {
        has_auth(name)
    };
    if !b {
        bail!("{} unauthorized", name)
    } else {
        Ok(CostedReturnType::new(0, NativeReturnType::Bool(true)))
    }
}

pub fn native_is_account<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    let mut account: u64 = 0u64;

    let addr = match accessor.get_address() {
        Ok(addr)  => addr,
        Err(e) => return Err(e),
    };

    for i in 0..8 {
        account |= addr.to_vec()[i] as u64;
        account <<= 8;
    }

    let exists = unsafe {
        is_account(account)
    };

    Ok(CostedReturnType::new(0, NativeReturnType::Bool(exists)))
}

pub fn native_read_action_data<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    let size = unsafe {
        action_data_size()
    };
    let mut msg:Vec<u8> = vec![0;size];
    unsafe {
        read_action_data((&mut msg).as_mut_ptr(), size);
    }
    Ok(CostedReturnType::new(0, NativeReturnType::ByteArray(ByteArray::new(msg))))
}

