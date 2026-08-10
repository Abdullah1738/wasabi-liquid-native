#![feature(rustc_private)]

extern crate rustc_demangle;

use std::env;
use std::fs;
use std::process::ExitCode;

const DEFINED_GLOBAL_TYPES: &str = "ABCDGINPRSTVWiu";
const UNDEFINED_GLOBAL_TYPES: &str = "Uwv";
const ANONYMOUS_DATA_TYPES: &str = "DRS";

enum Record<'a> {
    Header,
    Undefined,
    Defined { symbol_type: char, name: &'a str },
    Invalid,
}

fn is_hex_address(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn has_valid_prefix(fields: &[&str]) -> bool {
    fields.is_empty() || fields.last().is_some_and(|field| field.ends_with(':'))
}

fn one_character(value: &str) -> Option<char> {
    let mut characters = value.chars();
    let character = characters.next()?;
    characters.next().is_none().then_some(character)
}

fn parse_record(line: &str) -> Record<'_> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Record::Header;
    }

    let fields: Vec<_> = trimmed.split_whitespace().collect();
    if fields.len() >= 3
        && is_hex_address(fields[fields.len() - 3])
        && has_valid_prefix(&fields[..fields.len() - 3])
    {
        let Some(symbol_type) = one_character(fields[fields.len() - 2]) else {
            return Record::Invalid;
        };
        if DEFINED_GLOBAL_TYPES.contains(symbol_type) {
            return Record::Defined {
                symbol_type,
                name: fields[fields.len() - 1],
            };
        }
        return Record::Invalid;
    }

    if fields.len() >= 2 && has_valid_prefix(&fields[..fields.len() - 2]) {
        let Some(symbol_type) = one_character(fields[fields.len() - 2]) else {
            return Record::Invalid;
        };
        if UNDEFINED_GLOBAL_TYPES.contains(symbol_type) {
            return Record::Undefined;
        }
    }

    if !trimmed.chars().any(char::is_whitespace) && trimmed.ends_with(':') {
        return Record::Header;
    }

    Record::Invalid
}

fn is_llvm_anonymous_data_symbol(symbol_type: char, name: &str) -> bool {
    if !ANONYMOUS_DATA_TYPES.contains(symbol_type) {
        return false;
    }
    let name = name.strip_prefix('_').unwrap_or(name);
    let components: Vec<_> = name.split('.').collect();
    components.len() == 5
        && components[0] == "anon"
        && components[1].len() == 32
        && components[1]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !components[2].is_empty()
        && components[2].bytes().all(|byte| byte.is_ascii_digit())
        && components[3] == "llvm"
        && !components[4].is_empty()
        && components[4].bytes().all(|byte| byte.is_ascii_digit())
}

fn is_permitted_defined_global(symbol_type: char, name: &str) -> bool {
    rustc_demangle::try_demangle(name).is_ok() || is_llvm_anonymous_data_symbol(symbol_type, name)
}

fn rejected_lines(input: &str) -> Vec<String> {
    let mut recognized_records = 0usize;
    let mut rejected = Vec::new();
    for (index, line) in input.lines().enumerate() {
        match parse_record(line) {
            Record::Header => {}
            Record::Undefined => recognized_records += 1,
            Record::Defined { symbol_type, name } => {
                recognized_records += 1;
                if !is_permitted_defined_global(symbol_type, name) {
                    rejected.push(format!("line {}: {line}", index + 1));
                }
            }
            Record::Invalid => rejected.push(format!("line {}: {line}", index + 1)),
        }
    }
    if recognized_records == 0 {
        rejected.push("no recognized nm symbol records".to_owned());
    }
    rejected
}

fn expect(input: &str, accepted: bool) -> Result<(), String> {
    let rejected = rejected_lines(input);
    if rejected.is_empty() == accepted {
        Ok(())
    } else {
        Err(format!(
            "unexpected symbol-check result for {input:?}: {rejected:?}"
        ))
    }
}

fn self_test() -> Result<(), String> {
    expect(
        "archive.rlib(member.o):\n\
         0000000000000000 T _ZN4demo17h0123456789abcdefE\n\
         0000000000000000 T _RNvC4demo4item\n\
         archive.rlib(member.o): 0000000000000000 T _ZN5other17hfedcba9876543210E\n\
         0000000000000000 R anon.f99fed1169e43e329df3b547af841277.0.llvm.4185876869160636025\n\
         0000000000000000 D anon.0123456789abcdef0123456789abcdef.4.llvm.7\n\
         0000000000000000 S _anon.0123456789abcdef0123456789abcdef.4.llvm.7\n\
                          U plain_undefined_symbol\n\
         archive.rlib(member.o): w weak_undefined_symbol\n\
         archive.rlib(member.o): v weak_undefined_object\n",
        true,
    )?;
    expect("0000000000000000 T __ZN4demo17h0123456789abcdefE\n", true)?;
    expect("0000000000000000 T __RNvC4demo4item\n", true)?;

    for input in [
        "",
        "archive.rlib(member.o):\n",
        "garbage\n",
        "garbage header:\n0000000000000000 T _ZN4demo17h0123456789abcdefE\n",
        "T malformed_two_field_defined_record\n",
        "0000000000000000 T wallet_facts_export:\n",
        "0000000000000000 X _ZN4demo17h0123456789abcdefE\n",
        "0000000000000000 N plain_debug_export\n",
        "0000000000000000 P plain_unwind_export\n",
        "0000000000000000 S plain_data_export\n",
        "0000000000000000 T wallet_facts_export\n",
        "0000000000000000 T _ZNwallet_facts_export\n",
        "0000000000000000 T _Rwallet_facts_export\n",
        "0000000000000000 T _ZN4demo17h0123456789abcdefEgarbage\n",
        "0000000000000000 T anon.0123456789abcdef0123456789abcdef.4.llvm.7\n",
        "0000000000000000 W anon.0123456789abcdef0123456789abcdef.4.llvm.7\n",
        "0000000000000000 B anon.0123456789abcdef0123456789abcdef.4.llvm.7\n",
        "0000000000000000 R anon.0123456789ABCDEf0123456789abcdef.4.llvm.7\n",
        "0000000000000000 R anon.0123456789abcdef.4.llvm.7\n",
        "0000000000000000 R anon.0123456789abcdef0123456789abcdef.llvm.7\n",
        "0000000000000000 R anon.0123456789abcdef0123456789abcdef.x.llvm.7\n",
        "0000000000000000 R anon.0123456789abcdef0123456789abcdef.4.llvm.x\n",
        "0000000000000000 R anon.0123456789abcdef0123456789abcdef.4.llvm.7.extra\n",
    ] {
        expect(input, false)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let arguments: Vec<_> = env::args().collect();
    if arguments.len() == 2 && arguments[1] == "--self-test" {
        return match self_test() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    if arguments.len() != 2 {
        eprintln!("usage: check-rust-rlib-symbols NM_OUTPUT");
        return ExitCode::from(2);
    }
    let input = match fs::read_to_string(&arguments[1]) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("cannot read nm output: {error}");
            return ExitCode::from(2);
        }
    };
    let rejected = rejected_lines(&input);
    if rejected.is_empty() {
        ExitCode::SUCCESS
    } else {
        for line in rejected {
            eprintln!("{line}");
        }
        ExitCode::FAILURE
    }
}
