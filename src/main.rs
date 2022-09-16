#![allow(non_snake_case)]

extern crate nalgebra as na;
use na::base::{Matrix4x1, SMatrix, Vector4};

use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};

// AES
// Key

fn Rotate(byte: &mut [u8; 4]){
    let temp = byte[0];

    for i in 0..3 {
        byte[i] = byte[i + 1];
    }

    byte[3] = temp;
}

fn Rcon(mut byte: u8) -> u8 {
    let mut c: u8 = 1;

    if byte == 0 {
        return 0;
    }

    while byte != 1 {
        let b = c & 0x80;
        c <<= 1;
        if b == 0x80 {
            c ^= 0x1b;
        }
        byte -= 1;
    }

    return c;
}

fn ScheduleCore(byte: &mut [u8; 4], i: u8) {
    Rotate(byte);
    Sbox(byte);
    byte[0] ^= Rcon(i);
}

fn ExpandKey(initialKey: [u8; 32]) -> [u8; 240] {
    let mut temp: [u8; 4] = [0, 0, 0, 0];
    let mut c: u8 = 32;
    let mut i = 1;
    let mut key = [0; 240];

    for byte in initialKey {
        key[i as usize] = byte;
    }

    while c < 240 {
        for j in 0..4 {
            temp[j] = key[(j as u8 + c - 4) as usize];
        }

        if c % 32 == 0 {
            ScheduleCore(&mut temp, i);
            i += 1;
        }

        if c % 32 == 16 {
            Sbox(&mut temp);
        }

        for j in 0..4 {
            key[c as usize] = key[(c - 16) as usize] ^ temp[j];
            c += 1;
        }

        for j in 0..4 {
            key[c as usize] = key[c as usize - 32] ^ temp[j];
            c += 1;
        }
    }
    key
}

// Encrypt

fn Sbox(byte: &mut [u8; 4]) {
    let sbox: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    for i in 0..4 {
        byte[i] = sbox[byte[i] as usize];
    }
}

fn ShiftRows(matrix: &mut SMatrix<u8, 4, 4>) {
    let temp = matrix[(1, 0)];

    for i in 0..3 {
        matrix[(1, i)] = matrix[(1, i + 1)];
    }

    matrix[(1, 3)] = temp;

    let temp = matrix[(2, 0)];
    matrix[(2, 0)] = matrix[(2, 2)];
    matrix[(2, 2)] = temp;

    let temp = matrix[(2, 1)];
    matrix[(2, 1)] = matrix[(2, 3)];
    matrix[(2, 3)] = temp;

    let temp = matrix[(3, 3)];

    for i in (1..4).rev() {
        matrix[(3, i)] = matrix[(3, i - 1)];
    }

    matrix[(3, 0)] = temp;
}

fn MixColumns(matrix: &mut SMatrix<u8, 4, 4>) {
    for i in 0..4 {
        let c = Matrix4x1::new(
            matrix[(0, i)],
            matrix[(1, i)],
            matrix[(2, i)],
            matrix[(3, i)],
        );

        matrix[(0, i)] =
            FFM(2, c[(0, 0)]) ^ FFM(3, c[(1, 0)]) ^ FFM(1, c[(2, 0)]) ^ FFM(1, c[(3, 0)]);
        matrix[(1, i)] =
            FFM(1, c[(0, 0)]) ^ FFM(2, c[(1, 0)]) ^ FFM(3, c[(2, 0)]) ^ FFM(1, c[(3, 0)]);
        matrix[(2, i)] =
            FFM(1, c[(0, 0)]) ^ FFM(1, c[(1, 0)]) ^ FFM(2, c[(2, 0)]) ^ FFM(3, c[(3, 0)]);
        matrix[(3, i)] =
            FFM(3, c[(0, 0)]) ^ FFM(1, c[(1, 0)]) ^ FFM(1, c[(2, 0)]) ^ FFM(2, c[(3, 0)]);
    }
}

// Decryption

fn ReverseSbox(byte: &mut [u8; 4]) {
    let sbox: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    for i in 0..4 {
        for j in 0..=255 {
            if byte[i] == sbox[j as usize] {
                byte[i] = j;
                break;
            }
        }
    }
}

fn ReverseShiftRows(matrix: &mut SMatrix<u8, 4, 4>) {
    let temp = matrix[(1, 3)];

    for i in (1..4).rev() {
        matrix[(1, i)] = matrix[(1, i - 1)];
    }

    matrix[(1, 0)] = temp;

    let temp = matrix[(2, 2)];
    matrix[(2, 2)] = matrix[(2, 0)];
    matrix[(2, 0)] = temp;

    let temp = matrix[(2, 3)];
    matrix[(2, 3)] = matrix[(2, 1)];
    matrix[(2, 1)] = temp;

    let temp = matrix[(3, 0)];

    for i in 0..3 {
        matrix[(3, i)] = matrix[(3, i + 1)];
    }

    matrix[(3, 3)] = temp;
}

fn ReverseMixColumns(matrix: &mut SMatrix<u8, 4, 4>) {
    for i in 0..4 {
        let c = Matrix4x1::new(
            matrix[(0, i)],
            matrix[(1, i)],
            matrix[(2, i)],
            matrix[(3, i)],
        );

        matrix[(0, i)] =
            FFM(14, c[(0, 0)]) ^ FFM(11, c[(1, 0)]) ^ FFM(13, c[(2, 0)]) ^ FFM(9, c[(3, 0)]);
        matrix[(1, i)] =
            FFM(9, c[(0, 0)]) ^ FFM(14, c[(1, 0)]) ^ FFM(11, c[(2, 0)]) ^ FFM(13, c[(3, 0)]);
        matrix[(2, i)] =
            FFM(13, c[(0, 0)]) ^ FFM(9, c[(1, 0)]) ^ FFM(14, c[(2, 0)]) ^ FFM(11, c[(3, 0)]);
        matrix[(3, i)] =
            FFM(11, c[(0, 0)]) ^ FFM(13, c[(1, 0)]) ^ FFM(9, c[(2, 0)]) ^ FFM(14, c[(3, 0)]);
    }
}

// Control

fn PlainToMatrix(plain: &str) -> SMatrix<u8, 4, 4> {
    let mut plain = String::from(plain.trim_end());

    while plain.len() < 16 {
        plain.push(' ')
    }

    let plain = plain.as_bytes();

    SMatrix::from_columns(&[
        Vector4::new(plain[0], plain[1], plain[2], plain[3]),
        Vector4::new(plain[4], plain[5], plain[6], plain[7]),
        Vector4::new(plain[8], plain[9], plain[10], plain[11]),
        Vector4::new(plain[12], plain[13], plain[14], plain[15]),
    ])
}

fn AddKey(matrix: &mut SMatrix<u8, 4, 4>, key: &[u8]) {
    for i in 0..4 {
        for j in 0..4 {
            matrix[(i, j)] ^= key[i * 4 + j];
        }
    }
}

fn FFM(n1: u8, n2: u8) -> u8 {
    let mut a: u8 = n1;
    let mut b: u8 = n2;
    let mut p: u8 = 0;

    for _i in 0..=8 {
        if (b & 0b00000001) == 1 {
            p ^= a;
        }

        b = b >> 1;

        let carry = if (a & 0b10000000) == 128 { 1 } else { 0 };

        a = a << 1;

        if carry == 1 {
            a ^= 0x1b;
        }
    }

    p
}

fn Encrypt(matrix: &mut SMatrix<u8, 4, 4>, key: &[u8; 240]) {
    AddKey(matrix, &key[0 .. 16]);

    for round in 1..=13 {
        for i in 0..4 {
            let mut temp = [0; 4];

            for j in 0..4 { temp[j] = matrix[(i, j)]; }

            Sbox(&mut temp);

            for j in 0..4 { matrix[(i, j)] = temp[j]; }
        }

        ShiftRows(matrix);
        MixColumns(matrix);
        AddKey(matrix, &key[(round * 16) .. ((round * 16) + 16)]);
    }

    for i in 0..4 {
        let mut temp = [0; 4];

        for j in 0..4 { temp[j] = matrix[(i, j)]; }

        Sbox(&mut temp);

        for j in 0..4 { matrix[(i, j)] = temp[j]; }
    }

    ShiftRows(matrix);
    AddKey(matrix, &key[224 .. 240]);
}

fn Decrypt(matrix: &mut SMatrix<u8, 4, 4>, key: &[u8; 240]) {
    AddKey(matrix, &key[224 .. 240]);
    ReverseShiftRows(matrix);

    for i in 0..4 {
        let mut temp = [0; 4];
        
        for j in 0..4 { temp[j] = matrix[(i, j)]; }

        ReverseSbox(&mut temp);

        for j in 0..4 { matrix[(i, j)] = temp[j]; }
    }

    for round in (1..=13).rev() {
        AddKey(matrix, &key[(round * 16) .. ((round * 16) + 16)]);
        ReverseMixColumns(matrix);
        ReverseShiftRows(matrix);

        for i in 0..4 {
            let mut temp = [0; 4];
        
            for j in 0..4 { temp[j] = matrix[(i, j)]; }

            ReverseSbox(&mut temp);

            for j in 0..4 { matrix[(i, j)] = temp[j]; }
        }
    }

    AddKey(matrix, &key[0 .. 16]);
}

fn MatrixToText(matrix: SMatrix<u8, 4, 4>) -> String {
    let mut text = String::new();

    for i in 0..4 {
        for j in 0..4 {
            text.push(matrix[(j, i)] as char);
        }
    }

    text
}

fn MatrixToHex(matrix: SMatrix<u8, 4, 4>) -> [u8; 16] {
    let mut text: [u8; 16] = [0; 16];

    for i in 0..4 {
        for j in 0..4 {
            text[i * 4 + j] = matrix[(j, i)];
        }
    }

    text
}

// RSA
fn GenerateKey() -> (u128, u128, u128) {
    let p = 61;
    let q = 53;
    let n = p * q;
    let t = (p - 1) * (q - 1);

    let e = 17;
    let mut x = 0;
    let mut y = 0;
    gcd(e, t, &mut x, &mut y);
    let d = t + x;
    (n as u128, e as u128, d as u128)
}

fn gcd (e: i128, t: i128, x: &mut i128, y: &mut i128) -> i128 {
    if e == 0 {
        *x = 0;
        *y = 1;
        return t;
    }
    let mut x1 = 0;
    let mut y1 = 0;
    let gcd = gcd(t % e, e, &mut x1, &mut y1);
    *x = y1 - (t/e) * x1;
    *y = x1;
    return gcd;
}

fn EMod(m: u128, e: u128, n: u128) -> u128 {
    let mut c = 1;
    let mut f = 0;
    while f < e {
        f += 1;
        c = (m * c) % n;
    }
    c
}

#[tokio::main]
async fn main() {
    println!("Generating keys...");
    let (n, e, d) = GenerateKey();
    let initialKey = [0; 32];
    let key = ExpandKey(initialKey);
    println!("Generated keys");

    println!("Waiting for connection");
    let listener = TcpListener::bind("127.0.0.1:6142").await.expect("Could not bind port");
    let (mut socket, address) = listener.accept().await.expect("Could not accept listner");
    println!("Connected");

    let output = tokio::spawn(async move{
        let mut socket = TcpStream::connect(address).await.expect("failed to connect");
        let (mut rd, mut wr) = socket.split();

        let mut buf = vec![0; 128];

        loop {
            let n = rd.read(&mut buf).await.expect("failed to read");

            if n != 0 {
                println!("> {:?}", &buf[..n]);
            }
        }
    });

    let (mut rd, mut wr) = socket.split();

    loop {
        println!("Please input plain text");
        let mut plain: String = String::new();
        std::io::stdin()
            .read_line(&mut plain)
            .expect("Failed to read line");

        if plain.trim() == "exit" {
            break;
        }

        let mut matrix: Vec<SMatrix<u8, 4, 4>> = Vec::new();

        while plain.len() % 16 != 0 {
            plain.push(' ');
        }

        for i in 0..(&plain.len() / 16) {
            matrix.push(PlainToMatrix(&plain[i * 16 .. (i+1) * 16]));
            Encrypt(&mut matrix[i], &key);
        }

        for i in 0..(&plain.len() / 16) {
            println!("{:02X}", matrix[i]);
        }

        let mut message = Vec::new();

        for i in 0..(&plain.len() / 16) {
            message[i] = MatrixToHex(matrix[i]);
        }

        for i in 0..(&plain.len() / 16) {
            wr.write_all(&message[i]).await.expect("failed to write");
        }
    }
    
    output.await.unwrap();
}
/* 
#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:6142").await?;

    loop {
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let (mut rd, mut wr) = socket.split();
            
            if io::copy(&mut rd, &mut wr).await.is_err() {
                eprintln!("failed to copy");
            }
        });
    }
}
*/