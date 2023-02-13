use spectrum::cryptography::rsa::RSA;
use spectrum::cryptography::{encrypt, decrypt, aes::AES};
use spectrum::cryptography::aes::InitKey;
use spectrum::format::u8_to_hex;

use std::env;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot::{self, Sender};

use crate::key_transfer::{send_rsa_key, recive_init_key, recive_rsa_key};

mod key_transfer;

use key_transfer::send_init_key;

fn recive(address: SocketAddr) {
    tokio::spawn(async move {
        println!("Connecting");
        let mut socket = TcpStream::connect(address)
            .await
            .expect("failed to connect");
        println!("Connected");

        let (mut rd, mut wr) = socket.split();

        let rsa = RSA::new();

        send_rsa_key(&mut wr, &rsa).await;

        let init_key = InitKey::AES256([0; 32]);

        let init_key = recive_init_key(init_key, &mut rd, &rsa).await;

        let crypto = AES::from_init_key(init_key);

        let mut buf = vec![0; 128];

        loop {
            let n = rd.read(&mut buf).await.expect("failed to read");

            if n == 0 {
                break;
            }

            let cipher = u8_to_hex(buf.to_vec());

            let message = decrypt(&crypto, cipher).unwrap();

            println!("> {message}");
        }
    });
}

fn send(listening_address: SocketAddr, tx: Sender<SocketAddr>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(listening_address)
            .await
            .expect("Could not bind port");

        let (mut socket, connection_address) = listener.accept().await.expect("Could not accept listner");
        let (mut rd, mut wr) = socket.split();
        
        let rsa = recive_rsa_key(&mut rd).await;

        let crypto = AES::new();

        let init_key = crypto.init_key();
        send_init_key(&init_key, &mut wr, &rsa).await;

        tx.send(connection_address).unwrap();

        loop {
            let mut plain: String = String::new();
            std::io::stdin()
                .read_line(&mut plain)
                .expect("Failed to read line");

            if plain.trim() == "exit" {
                break;
            }

            let message = encrypt(&crypto, plain);

            wr.write_all(message.as_bytes()).await.expect("failed to write");
        }
    })
}

#[tokio::main]
async fn main() {
    // Getting enviroment arguments
    let args: Vec<String> = env::args().collect();

    let index = args.iter().position(|x| x == "-ip").unwrap();
    let ip = &args[index + 1];

    let index = args.iter().position(|x| x == "-p").unwrap();
    let port = &args[index + 1];

    let listening_address: SocketAddr = (ip.to_owned() + ":" + port)
        .parse()
        .expect("failed to parse address");


    let (tx, rx) = oneshot::channel();

    let handler = send(listening_address, tx);

    // If there is a connection address -> initialise connection address with that value otherwise none
    if let Some(index) = args.iter().position(|x| x == "-c") {
        let connection_address = (args[index + 1].trim().to_owned() + ":" + port.trim())
            .parse()
            .unwrap();

        recive(connection_address);
    } else {
        let connection_address = rx.await.unwrap();

        recive(connection_address);
    }

    handler.await.unwrap();
}
