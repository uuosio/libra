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
    fn is_account( name: u64 ) -> bool;
    fn current_receiver() -> u64;

    fn db_store_i64(scope: u64, table: u64, payer: u64, id: u64,  data: *const u8, len: size_t) -> i32;
    fn db_update_i64(iterator: i32, payer: u64, data: *const u8, len: size_t);
    fn db_remove_i64(iterator: i32);
    fn db_get_i64(iterator: i32, data: *mut u8, len: size_t) -> size_t;
    fn db_next_i64(iterator: i32, primary: *mut u64) -> i32;
    fn db_previous_i64(iterator: i32, primary: *mut u64) -> i32;
    fn db_find_i64(code: u64, scope: u64, table: u64, id: u64) -> i32;
    fn db_lowerbound_i64(code: u64, scope: u64, table: u64, id: u64) -> i32;
    fn db_upperbound_i64(code: u64, scope: u64, table: u64, id: u64) -> i32;
    fn db_end_i64(code: u64, scope: u64, table: u64) -> i32;
}

pub fn vm_db_store_i64(scope: u64, table: u64, payer: u64, id: u64,  data: &[u8]) -> i32{
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

pub fn vm_db_get_i64(iterator: i32, data: &mut [u8]) -> size_t {
    unsafe {
        db_get_i64(iterator, data.as_mut_ptr(), data.len())
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

pub fn native_store_i64<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    println!("+++++++++++native_store_i64");
    let data = accessor.get_byte_array()?;
    let id = accessor.get_u64()?;
    let payer = accessor.get_u64()?;
    let table = accessor.get_u64()?;
    let scope = accessor.get_u64()?;
    println!("+++++++++++{} {} {} {} {}", scope, table, payer, id, data);
    let ret = vm_db_store_i64(scope, table, payer, id, data.as_bytes());
    Ok(CostedReturnType::new(0, NativeReturnType::UInt64(ret as u64)))
}

//pub fn vm_db_update_i64(iterator: i32, payer: u64, data: &[u8])
pub fn native_update_i64<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    println!("+++++++++++native_update_i64");
    let data = accessor.get_byte_array()?;
    let payer = accessor.get_u64()?;
    let iterator = accessor.get_u64()?;
    let ret = vm_db_update_i64(iterator as i32, payer, data.as_bytes());
    Ok(CostedReturnType::new(0, NativeReturnType::Void))
}

pub fn native_remove_i64<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    println!("+++++++++++native_remove_i64");
    let iterator = accessor.get_u64()?;
    let ret = vm_db_remove_i64(iterator as i32);
    Ok(CostedReturnType::new(0, NativeReturnType::Void))
}


//pub fn vm_db_get_i64(iterator: i32, data: &mut [u8]);
pub fn native_get_i64<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    println!("+++++++++++native_get_i64");
    let iterator = accessor.get_u64()?;

    let data_size = vm_db_get_i64(iterator as i32, &mut []);
    let mut data: Vec<u8> = vec![0;data_size];
    let ret = vm_db_get_i64(iterator as i32, &mut data);
    println!("{} {:?}", data_size, data);
    Ok(CostedReturnType::new(0, NativeReturnType::ByteArray(ByteArray::new(data))))
}

//pub fn vm_db_next_i64(iterator: i32, primary: &mut u64) -> i32;
pub fn native_next_i64<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    println!("+++++++++++native_next_i64");
    let iterator = accessor.get_u64()?;
    let mut primary: u64 = 0u64;
    let iterator = vm_db_next_i64(iterator as i32, &mut primary);
    Ok(CostedReturnType::new(0, NativeReturnType::UInt64(iterator as u64)))
}

//pub fn vm_db_previous_i64(iterator: i32, primary: &mut u64) -> i32;
pub fn native_previous_i64<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    println!("+++++++++++native_next_i64");
    let iterator = accessor.get_u64()?;
    let mut primary: u64 = 0u64;
    let iterator = vm_db_previous_i64(iterator as i32, &mut primary);
    Ok(CostedReturnType::new(0, NativeReturnType::UInt64(iterator as u64)))
}

//pub fn vm_db_find_i64(code: u64, scope: u64, table: u64, id: u64) -> i32;
pub fn native_find_i64<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    println!("+++++++++++native_next_i64");
    let id = accessor.get_u64()?;
    let table = accessor.get_u64()?;
    let scope = accessor.get_u64()?;
    let code = accessor.get_u64()?;

    let iterator = vm_db_find_i64(code, scope, table, id);
    Ok(CostedReturnType::new(0, NativeReturnType::UInt64(iterator as u64)))
}

//pub fn vm_db_lowerbound_i64(code: u64, scope: u64, table: u64, id: u64) -> i32;
pub fn native_lowerbound_i64<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    println!("+++++++++++native_next_i64");
    let id = accessor.get_u64()?;
    let table = accessor.get_u64()?;
    let scope = accessor.get_u64()?;
    let code = accessor.get_u64()?;

    let iterator = vm_db_lowerbound_i64(code, scope, table, id);
    Ok(CostedReturnType::new(0, NativeReturnType::UInt64(iterator as u64)))
}

//pub fn vm_db_upperbound_i64(code: u64, scope: u64, table: u64, id: u64) -> i32;
pub fn native_upperbound_i64<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    println!("+++++++++++native_next_i64");
    let id = accessor.get_u64()?;
    let table = accessor.get_u64()?;
    let scope = accessor.get_u64()?;
    let code = accessor.get_u64()?;

    let iterator = vm_db_upperbound_i64(code, scope, table, id);
    Ok(CostedReturnType::new(0, NativeReturnType::UInt64(iterator as u64)))
}

//pub fn vm_db_end_i64(code: u64, scope: u64, table: u64) -> i32;
pub fn native_end_i64<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    println!("+++++++++++native_next_i64");
    let table = accessor.get_u64()?;
    let scope = accessor.get_u64()?;
    let code = accessor.get_u64()?;

    let iterator = vm_db_end_i64(code, scope, table);
    Ok(CostedReturnType::new(0, NativeReturnType::UInt64(iterator as u64)))
}
