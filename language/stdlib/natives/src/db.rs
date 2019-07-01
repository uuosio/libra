// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::dispatch::{CostedReturnType, NativeReturnType, Result, StackAccessor};
use bitcoin_hashes::{hash160, sha256, Hash};
use std::borrow::Borrow;
use tiny_keccak::Keccak;
use types::byte_array::ByteArray;

pub fn native_print<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    let hash_arg = accessor.get_byte_array()?;
    println!("{}", hash_arg);
    Ok(CostedReturnType::new(0, NativeReturnType::Bool(true)))
}

//    native public store_i64(scope: u64, table: u64, payer: u64, id: u64,  data: bytearray);

pub fn native_store_i64<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    println!("+++++++++++native_store_i64");
//    let scope = accessor.get_uint64()?;
//    println!("+++++++++++{}", scope);
/*
    let table = accessor.get_byte_array()?;
    let payer = accessor.get_byte_array()?;
    let id = accessor.get_byte_array()?;
*/    
    let data = accessor.get_byte_array()?;
    let id = accessor.get_uint64()?;
    let payer = accessor.get_uint64()?;
    let table = accessor.get_uint64()?;
    let scope = accessor.get_uint64()?;

    println!("+++++++++++{} {} {} {} {}", scope, table, payer, id, data);
    Ok(CostedReturnType::new(0, NativeReturnType::UInt64(0)))
}
