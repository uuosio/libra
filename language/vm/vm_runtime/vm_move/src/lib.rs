// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Test infrastructure for the Libra VM.
//!
//! This crate contains helpers for executing tests against the Libra VM.

use bytecode_verifier::{VerifiedModule, VerifiedScript};
use compiler::Compiler;
use data_store::FakeDataStore;
use types::{
    access_path::AccessPath, account_address::AccountAddress, transaction::TransactionArgument,
};

use vm::{
    access::ModuleAccess,
    errors::*,
    file_format::{Bytecode, CodeOffset, CompiledModule, CompiledScript, StructDefinitionIndex},
    transaction_metadata::TransactionMetadata,
};

use vm_runtime::{
    execute_function, execute_function_ex, static_verify_program,
    data_cache::{RemoteCache, TransactionDataCache},
    code_cache::module_cache::{ModuleCache, VMModuleCache},
    loaded_data::{
        function::{FunctionRef, FunctionReference},
        loaded_module::LoadedModule,
    },
    txn_executor::TransactionExecutor,
};

use vm_cache_map::Arena;
use std::collections::HashMap;
use lazy_static::lazy_static;

use vm::assert_ok;
use std::fs;

#[cfg(test)]
mod tests;

pub mod account;
pub mod account_universe;
pub mod common_transactions;
pub mod compile;
pub mod data_store;
pub mod executor;
pub mod gas_costs;
mod proptest_types;

use std::time::{SystemTime, UNIX_EPOCH};

/// Compiles a program with the given arguments and executes it in the VM.
pub fn compile_and_execute(program: &str, args: Vec<TransactionArgument>) -> VMResult<()> {
    let address = AccountAddress::default();
    let compiler = Compiler {
        code: program,
        address,
        ..Compiler::default()
    };
    let compiled_program = compiler.into_compiled_program().expect("Failed to compile");
    let (verified_script, modules) =
        verify(&address, compiled_program.script, compiled_program.modules);
    execute(verified_script, args, modules)
}

pub fn execute(
    script: VerifiedScript,
    args: Vec<TransactionArgument>,
    modules: Vec<VerifiedModule>,
) -> VMResult<()> {
    // set up the DB
    let mut data_view = FakeDataStore::default();
    data_view.set(
        AccessPath::new(AccountAddress::random(), vec![]),
        vec![0, 0],
    );
    execute_function(script, modules, args, &data_view)
}

/*
pub fn execute_function_ex(
    module_cache: VMModuleCache,
    loaded_main: LoadedModule,
    entry_func: FunctionRef,
    data_cache: &RemoteCache,
)
*/

pub fn execute_ex(
    script: VerifiedScript,
    args: Vec<TransactionArgument>,
    modules: Vec<VerifiedModule>,
) -> VMResult<()> {
    // set up the DB
    let mut data_view = FakeDataStore::default();
    data_view.set(
        AccessPath::new(AccountAddress::random(), vec![]),
        vec![0, 0],
    );

    let allocator = Arena::new();
    let module_cache = VMModuleCache::new(&allocator);
    let main_module = script.into_module();
    let loaded_main = LoadedModule::new(main_module);
    let entry_func = FunctionRef::new(&loaded_main, CompiledScript::MAIN_INDEX);

    for m in modules {
        module_cache.cache_module(m);
    }

    execute_function_ex(module_cache, entry_func, &data_view)
}

fn verify(
    sender_address: &AccountAddress,
    compiled_script: CompiledScript,
    modules: Vec<CompiledModule>,
) -> (VerifiedScript, Vec<VerifiedModule>) {
    let (verified_script, verified_modules) =
        static_verify_program(sender_address, compiled_script, modules)
            .expect("verification failure");
    (verified_script, verified_modules)
}

#[macro_export]
macro_rules! assert_prologue_parity {
    ($e1:expr, $e2:expr, $e3:pat) => {
        assert_matches!($e1, Some($e3));
        assert_matches!($e2, TransactionStatus::Discard($e3));
    };
}

#[macro_export]
macro_rules! assert_prologue_disparity {
    ($e1:expr => $e2:pat, $e3:expr => $e4:pat) => {
        assert_matches!($e1, $e2);
        assert_matches!($e3, &$e4);
    };
}

lazy_static! {
    // Since it's mutable and shared, use mutex
    static ref codecache: HashMap<u64, VerifiedScript> = HashMap::new();
}

use std::sync::Mutex;

#[derive(Debug, Clone)]
struct ContractCache {
    script: Option<VerifiedScript>,
    modules: Option<Vec<VerifiedModule>>
}

lazy_static! {
    static ref HASHMAP: Mutex<HashMap<u64, ContractCache>> = {
        let mut m = HashMap::new();
        Mutex::new(m)
    };    
}

pub fn compile_and_execute2(receiver:u64, program: &str, args: Vec<TransactionArgument>) -> VMResult<()> {
//    let codecache: &'static HashMap<u64, VerifiedScript> = &mut HashMap::new();
    let mut map = HASHMAP.lock().unwrap();
    match map.get(&receiver) {
        Some(cache) => {
        },
        None => {
            let mut cache = ContractCache{script:None, modules:None};
            let address = AccountAddress::default();
            let compiler = Compiler {
                code: program,
                address,
                ..Compiler::default()
            };
            let compiled_program = compiler.into_compiled_program().expect("Failed to compile");
            let (verified_script, modules) =
                verify(&address, compiled_program.script, compiled_program.modules);
            cache.script = Some(verified_script);
            cache.modules = Some(modules);
            map.insert(receiver, cache);
        }
    }

    let start = SystemTime::now();
    let duration_start = start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let s = map.get(&receiver);
    match map.get(&receiver) {
        Some(cache) => {
            let ret = execute_ex(cache.clone().script.unwrap(), args, cache.clone().modules.unwrap());
        //    let s = map.get(&receiver);
        //    PRIVILEGES.insert("Jim", vec!["user"]);
            let end = SystemTime::now();
            let duration_end = end.duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            println!("+++++cost: {:?}", duration_end - duration_start);
            return ret;
        },
        None => {
            Ok(Ok(()))
        },
    }
}

extern crate libc;
use libc::size_t;
use std::slice;
use std::str;

#[no_mangle]
pub extern fn vm_setcode(receiver: u64, mut ptr: *mut u8, size: size_t) -> i32
{
    let mut map = HASHMAP.lock().unwrap();
    map.remove(&receiver);
    return 0;
}

#[no_mangle]
pub extern fn vm_apply(receiver: u64, code: u64, action: u64, mut ptr: *mut u8, size: size_t) -> i32
{
//    println!("++++++++++++++++++hello, apply!!!!!!!!!{}{}{}", receiver, code, action);
    let program = unsafe { slice::from_raw_parts_mut(ptr, size) };
    let program2 = str::from_utf8(program).unwrap();
    println!("program2 {:?}", program2);
/*
    let program = fs::read_to_string("./contracts/native_test.mvir")
            .expect("Something went wrong reading the file");
*/
    assert_ok!(compile_and_execute2(receiver, &program2, vec![]));
//    test_open_publishing();
    return 0;
}

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