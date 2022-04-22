#![allow(arithmetic_overflow)]
use std::env;
use std::fs;
use std::io;
use wyd2encdec::encdec::{
    decrypt, decrypt_non_null, encrypt, handle_packets, read_keys, read_raw_file,
};

// This is the main function
fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        panic!("Not enough arguments");
    }
    let mut keys: [u8; 512] = [0; 512];
    read_keys(&args[1], &mut keys);
    let mut encrypted_file_raw = read_raw_file(&args[3]);
    let mut decrypted_file_raw = read_raw_file(&args[4]);
    handle_packets(&decrypted_file_raw);
    decrypt_non_null(&mut encrypted_file_raw, &keys);
    encrypted_file_raw = read_raw_file(&args[3]);
    match args[2].as_str() {
        "enc" => fs::write("./encoded.bin", encrypt(&mut decrypted_file_raw, &keys))
            .expect("File should be available for write."),
        "dec" => fs::write("./decoded.bin", decrypt(&mut encrypted_file_raw, &keys))
            .expect("File should be available for write."),
        _ => unreachable!("Unknown argument"),
    }
    Ok(())
}
