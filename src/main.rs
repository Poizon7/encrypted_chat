use spectrum::cryptography::{
    aes::{self, InitKey},
    rsa,
};
use std::env;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot::{self, Sender};

async fn send_init_key<const N: usize>(
    init_key: &Option<[u8; N]>,
    wr: &mut WriteHalf<'_>,
    pe: u128,
    pn: u128,
) {
    if let Some(init_key) = init_key {
        for i in 0..N {
            wr.write_u128(rsa::Decrypt(init_key[i] as u128, pe, pn))
                .await
                .expect("failed to write aes key");
        }
    }
}

async fn recive_init_key(
    init_key: &mut InitKey,
    rd: &mut ReadHalf<'_>,
    tx: Sender<aes::InitKey>,
    d: u128,
    n: u128,
) {
    *init_key = match init_key {
        aes::InitKey::Bit128(init_key) => match init_key {
            Some(init_key) => aes::InitKey::Bit128(Some(*init_key)),
            None => {
                let mut init_key = [0; 16];
                for i in 0..16 {
                    init_key[i] =
                        rsa::Decrypt(rd.read_u128().await.expect("failed to read aes key"), d, n)
                            as u8;
                }
                let init_key = aes::InitKey::Bit128(Some(init_key));
                tx.send(init_key.clone()).expect("failed to send");
                init_key
            }
        },
        aes::InitKey::Bit192(init_key) => match init_key {
            Some(init_key) => aes::InitKey::Bit192(Some(*init_key)),
            None => {
                let mut init_key = [0; 24];
                for i in 0..24 {
                    init_key[i] =
                        rsa::Decrypt(rd.read_u128().await.expect("failed to read aes key"), d, n)
                            as u8;
                }
                let init_key = aes::InitKey::Bit192(Some(init_key));
                tx.send(init_key.clone()).expect("failed to send");
                init_key
            }
        },
        aes::InitKey::Bit256(init_key) => match init_key {
            Some(init_key) => aes::InitKey::Bit256(Some(*init_key)),
            None => {
                let mut init_key = [0; 32];
                for i in 0..32 {
                    init_key[i] =
                        rsa::Decrypt(rd.read_u128().await.expect("failed to read aes key"), d, n)
                            as u8;
                }
                let init_key = aes::InitKey::Bit256(Some(init_key));
                tx.send(init_key.clone()).expect("failed to send");
                init_key
            }
        },
    }
}

fn recive(
    address: SocketAddr,
    mut init_key: aes::InitKey,
    n: u128,
    e: u128,
    d: u128,
    tx: Sender<aes::InitKey>,
) {
    tokio::spawn(async move {
        println!("Connecting");
        let mut socket = TcpStream::connect(address)
            .await
            .expect("failed to connect");
        println!("Connected");
        let (mut rd, mut wr) = socket.split();

        wr.write_u128(n).await.expect("failed to send n");
        wr.write_u128(e).await.expect("failed to send e");

        let mut buf = vec![0; 128];

        recive_init_key(&mut init_key, &mut rd, tx, d, n).await;

        let key = aes::generate_key(&mut init_key);

        loop {
            let n = rd.read(&mut buf).await.expect("failed to read");

            if n == 0 {
                break;
            }

            let mut crypt = Vec::new();

            for i in 0..n / 16 {
                let mut temp = [0; 16];
                for j in 0..16 {
                    temp[j] = buf[i * 16 + j];
                }
                crypt.push(temp);
            }

            let message = aes::decrypt(crypt, &key);

            println!("> {}", message);
        }
    });
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

    let mut init_key = aes::InitKey::Bit256(None);

    // If there is a connection address -> initialise connection address with that value otherwise none
    let connection_address = if let Some(index) = args.iter().position(|x| x == "-c") {
        Some(
            (args[index + 1].trim().to_owned() + ":" + port.trim())
                .parse()
                .unwrap(),
        )
    } else {
        aes::generate_key(&mut init_key);
        None
    };

    let (n, e, d) = rsa::GenerateKey();
    let (tx, rx) = oneshot::channel::<aes::InitKey>();
    let (tx2, _rx2) = oneshot::channel::<aes::InitKey>();

    // Start listener
    let listening_handler = tokio::spawn(async move {
        let listener = TcpListener::bind(listening_address)
            .await
            .expect("Could not bind port");

        listener.accept().await.expect("Could not accept listner")
    });

    // If there is a connection address -> connect then wait for listener otherwise do in opposite order, return socket
    println!("Wainting for connection");
    let mut socket = if let Some(address) = connection_address {
        recive(address, init_key.clone(), n, e, d, tx);
        let (socket, _) = listening_handler.await.unwrap();
        socket
    } else {
        let (socket, address) = listening_handler.await.unwrap();

        let address = SocketAddr::new(
            address.ip(),
            port.trim().parse().expect("failed to parse port"),
        );

        recive(address, init_key.clone(), n, e, d, tx2);
        socket
    };

    let (mut rd, mut wr) = socket.split();

    let pn = rd.read_u128().await.expect("failed to read n");
    let pe = rd.read_u128().await.expect("failed to read e");

    let key = if connection_address.is_none() {
        match init_key {
            aes::InitKey::Bit128(init_key) => send_init_key(&init_key, &mut wr, pe, pn).await,
            aes::InitKey::Bit192(init_key) => send_init_key(&init_key, &mut wr, pe, pn).await,
            aes::InitKey::Bit256(init_key) => send_init_key(&init_key, &mut wr, pe, pn).await,
        }
        aes::generate_key(&mut init_key)
    } else {
        let mut init_key = rx.await.expect("sender droped");
        aes::generate_key(&mut init_key)
    };

    // Comunication loop
    loop {
        let mut plain: String = String::new();
        std::io::stdin()
            .read_line(&mut plain)
            .expect("Failed to read line");

        if plain.trim() == "exit" {
            break;
        }

        let message = aes::encrypt(&mut plain, &key);

        for i in 0..message.len() {
            wr.write_all(&message[i]).await.expect("failed to write");
        }
    }
}
