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