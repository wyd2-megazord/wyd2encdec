use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

//MsgHeader defines the basic struct for a WYD2 packet header
struct MsgHeader {
	size:       u16, //Packet size
	key:        u8,  //Key used as seed for enc/dec
	hash:       u8,  //Hash generated to validate the process
	code:       i16, //Internal packet identifier
	index:      i16, //Index from the user that sent the packet
    timestamp:  u32 //Timestamp usually get right before starting the enc/dec process
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

// This is the main function
fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        panic!("Not enough arguments");
    }
    let mut keys: [u8; 512] = [0; 512];
    read_keys(&args[1], &mut keys);
    Ok(())
}