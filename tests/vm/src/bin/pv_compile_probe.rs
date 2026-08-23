//! Compile a .sil source with the in-process compiler and print the script
//! hex + state layout, for byte-comparison against the silverc binary's
//! artifact (toolchain-consistency diagnostic).

use std::{env, fs};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 2 {
        eprintln!("usage: pv_compile_probe <source.sil> <constructor-args.json>");
        std::process::exit(1);
    }
    let source = fs::read_to_string(&args[0]).expect("read source");
    let ctor_json = fs::read_to_string(&args[1]).expect("read args");
    let constructor_args: Vec<Expr<'_>> = serde_json::from_str(&ctor_json).expect("parse args");
    let contract = compile_contract(Box::leak(source.into_boxed_str()), &constructor_args, CompileOptions::default())
        .expect("compile");
    println!(
        "{{\"len\":{},\"start\":{},\"stateLen\":{},\"script\":\"{}\"}}",
        contract.script.len(),
        contract.state_layout.start,
        contract.state_layout.len,
        contract.script.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
}
