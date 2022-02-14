#!/bin/bash
cargo build
./target/debug/rust ../data/keys.dat enc ../data/packets/lock-password/packets-encrypted.bin ../data/packets/lock-password/packets-decrypted.bin