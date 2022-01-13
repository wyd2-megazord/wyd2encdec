#![allow(arithmetic_overflow)]
use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

//MsgHeader defines the basic struct for a WYD2 packet header
#[repr(C)]
struct MsgHeader {
    size: u16,      //Packet size
    key: u8,        //Key used as seed for enc/dec
    hash: u8,       //Hash generated to validate the process
    code: i16,      //Internal packet identifier
    index: i16,     //Index from the user that sent the packet
    timestamp: u32, //Timestamp usually get right before starting the enc/dec process
}

fn read_keys(file_path: &String, keys: &mut [u8]) -> () {
    // Create a path to the desired file
    let path = Path::new(&file_path);
    let mut file = match File::open(&path) {
        Err(why) => panic!("Failed to open the keys file: {}", why),
        Ok(file) => file,
    };
    // read up to 512 bytes
    let n = match file.read(keys) {
        Err(why) => panic!("Failed to read the keys file: {}", why),
        Ok(n) => n,
    };
    if n != 512 {
        panic!("Failed to read the keys file")
    }
}

fn read_raw_file(file_path: &String) -> Vec<u8> {
    // Create a path to the desired file
    let path = Path::new(&file_path);
    let mut file = match File::open(&path) {
        Err(why) => panic!("Failed to open the keys file: {}", why),
        Ok(file) => file,
    };
    let mut vec_data = Vec::new();
    match file.read_to_end(&mut vec_data) {
        Err(why) => panic!("Failed to read the keys file: {}", why),
        Ok(n) => n,
    };
    vec_data
}

fn encrypt(raw_data: &mut Vec<u8>, keys: &[u8]) -> Vec<u8> {
    let mut index: isize = 0;
    let end_index: isize = raw_data.len() as isize;

    while index != end_index {
        let packet_size =
            ((raw_data[index as usize + 1] as isize) << 8) + raw_data[index as usize] as isize;
        let mut key = keys[(raw_data[index as usize + 2] as usize) << 1] as usize;
        let mut j = 4;
        while j < packet_size {
            let mapped_key = keys[((key % 256) << 1) + 1] as u32;
            let current_index = (index + j) as usize;
            let mut off: u8 = raw_data[current_index];
            match j & 3 {
                0 => off = off.wrapping_add((mapped_key << 1) as u8),
                1 => off = off.wrapping_sub((mapped_key >> 3) as u8),
                2 => off = off.wrapping_add((mapped_key << 2) as u8),
                _ => off = off.wrapping_sub((mapped_key >> 5) as u8),
            }
            raw_data[current_index] = off;
            j += 1;
            key += 1;
        }
        index += packet_size;
    }
    raw_data.to_vec()
}

fn decrypt(raw_data: &mut Vec<u8>, keys: &[u8]) -> Vec<u8> {
    let mut index: isize = 0;
    let end_index: isize = raw_data.len() as isize;
    let ptr: *const u8 = raw_data.as_ptr();

    while index != end_index {
        unsafe {
            let header = ptr.offset(index) as *const MsgHeader;
            let packet_size = (*header).size as isize;
            let mut j = 4;
            let mut key = keys[((*header).key as usize) << 1] as usize;
            while j < packet_size {
                let mapped_key = keys[((key % 256) << 1) + 1] as u32;
                let current_index = (index + j) as usize;
                let off = ptr.offset(current_index as isize) as *mut u8;
                match j & 3 {
                    0 => *off = (*off).wrapping_sub((mapped_key << 1) as u8),
                    1 => *off = (*off).wrapping_add((mapped_key as i32 >> 3) as u8),
                    2 => *off = (*off).wrapping_sub((mapped_key << 2) as u8),
                    _ => *off = (*off).wrapping_add((mapped_key as i32 >> 5) as u8),
                }
                j += 1;
                key += 1;
            }
            index += packet_size;
        }
    }
    raw_data.to_vec()
}

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
    match args[2].as_str() {
        "enc" => fs::write("./encoded.bin", encrypt(&mut decrypted_file_raw, &keys))
            .expect("Unable to write file"),
        "dec" => fs::write("./decoded.bin", decrypt(&mut encrypted_file_raw, &keys))
            .expect("Unable to write file"),
        _ => panic!("Unknown argument"),
    }
    Ok(())
}
