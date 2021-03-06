// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::dispatch::{CostedReturnType, NativeReturnType, Result, StackAccessor};
use bitcoin_hashes::{hash160, sha256, Hash};
use std::borrow::Borrow;
use tiny_keccak::Keccak;
use types::byte_array::ByteArray;

const HASH_LENGTH: usize = 32;
const KECCAK_COST: u64 = 30;
const RIPEMD_COST: u64 = 35;
const SHA2_COST: u64 = 30;
const SHA3_COST: u64 = 30;

pub fn native_keccak_256<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    let mut hash = [0u8; HASH_LENGTH];
    let mut keccak = Keccak::new_keccak256();

    let hash_arg = accessor.get_byte_array()?;
    let native_cost = KECCAK_COST * hash_arg.len() as u64;

    println!("{}", hash_arg);

    keccak.update(hash_arg.as_bytes());
    keccak.finalize(&mut hash);

    let native_return = NativeReturnType::ByteArray(ByteArray::new(hash.to_vec()));
    Ok(CostedReturnType::new(native_cost, native_return))
}

pub fn native_ripemd_160<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    let hash_arg = accessor.get_byte_array()?;
    let native_cost = RIPEMD_COST * hash_arg.len() as u64;
    let hash = hash160::Hash::hash(hash_arg.as_bytes());
    let hash_ref: &[u8] = hash.borrow();
    let native_return = NativeReturnType::ByteArray(ByteArray::new(hash_ref.to_vec()));

    Ok(CostedReturnType::new(native_cost, native_return))
}

pub fn native_sha2_256<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    let hash_arg = accessor.get_byte_array()?;
    let native_cost = SHA2_COST * hash_arg.len() as u64;
    let hash = sha256::Hash::hash(hash_arg.as_bytes());
    let hash_ref: &[u8] = hash.borrow();
    let native_return = NativeReturnType::ByteArray(ByteArray::new(hash_ref.to_vec()));

    Ok(CostedReturnType::new(native_cost, native_return))
}

pub fn native_sha3_256<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    let mut hash = [0u8; HASH_LENGTH];
    let mut keccak = Keccak::new_sha3_256();

    let hash_arg = accessor.get_byte_array()?;
    let native_cost = SHA3_COST * hash_arg.len() as u64;

    keccak.update(hash_arg.as_bytes());
    keccak.finalize(&mut hash);

    let native_return = NativeReturnType::ByteArray(ByteArray::new(hash.to_vec()));
    Ok(CostedReturnType::new(native_cost, native_return))
}

pub fn native_print<T: StackAccessor>(mut accessor: T) -> Result<CostedReturnType> {
    let hash_arg = accessor.get_byte_array()?;
    println!("{}", hash_arg);
    Ok(CostedReturnType::new(0, NativeReturnType::Bool(true)))
}