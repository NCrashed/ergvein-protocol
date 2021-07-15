extern crate ergvein_protocol;
extern crate rand;

use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use ergvein_protocol::message::*;
use rand::{thread_rng, Rng};

fn main() {
    // This example establishes a connection to a Bitcoin node, sends the intial
    // "version" message, waits for the reply, and finally closes the connection.
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("not enough arguments");
        process::exit(1);
    }

    let str_address = &args[1];

    let address: SocketAddr = str_address.parse().unwrap_or_else(|error| {
        eprintln!("Error parsing address: {:?}", error);
        process::exit(1);
    });

    let filters_start: u64 = args[2].parse().unwrap();
    let amount: u32 = args[3].parse().unwrap();

    let version_message = build_version_message();

    if let Ok(mut stream) = TcpStream::connect(address) {
        // Send the message
        let _ = stream.write_all(serialize(&version_message).as_slice());
        println!("Sent version message");

        // Setup StreamReader
        let read_stream = stream.try_clone().unwrap();
        let mut stream_reader = StreamReader::new(read_stream, None);
        loop {
            // Loop an retrieve new messages
            let reply: Message = stream_reader.read_next().unwrap();
            match reply {
                Message::Version(_) => {
                    println!("Received version message: {:?}", reply);

                    let second_message = Message::VersionAck;

                    let _ = stream.write_all(serialize(&second_message).as_slice());
                    println!("Sent verack message");
                }
                Message::VersionAck => {
                    println!("Received verack message: {:?}", reply);

                    let msg = Message::GetFilters(FiltersReq {
                        amount: amount,
                        start: filters_start,
                        currency: Currency::Btc,
                    });
                    let _ = stream.write_all(serialize(&msg).as_slice());
                }
                Message::Filters(msg) => {
                    println!("Got filters!");
                    println!("{}", msg);
                    break;
                }
                _ => {
                    println!("Received unknown message: {:?}", reply);
                    break;
                }
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
    } else {
        eprintln!("Failed to open connection");
    }
}

fn build_version_message() -> Message {
    // "standard UNIX timestamp in seconds"
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time error")
        .as_secs();

    // "Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self."
    let mut rng = thread_rng();
    let nonce: [u8; 8] = rng.gen();

    // Construct the message
    Message::Version(VersionMessage {
        version: Version::current(),
        time: timestamp,
        nonce,
        scan_blocks: vec![],
    })
}
