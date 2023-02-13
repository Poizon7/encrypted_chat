use spectrum::cryptography::aes::InitKey;
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use spectrum::cryptography::rsa::RSA;
use spectrum::format::{array_to_vec, vec_to_array16, vec_to_array24, vec_to_array32};

pub async fn send_init_key(
    init_key: &InitKey,
    wr: &mut WriteHalf<'_>,
    rsa: &RSA
) {
    let init_key = match init_key {
        InitKey::AES128(init_key) => array_to_vec(*init_key),
        InitKey::AES192(init_key) => array_to_vec(*init_key),
        InitKey::AES256(init_key) => array_to_vec(*init_key)
    };
    let init_key = rsa.encrypt(init_key);

    for byte in init_key {
        wr.write_u128(byte)
            .await
            .expect("failed to write aes key");
    }
}

pub async fn recive_init_key(
    init_key: InitKey,
    rd: &mut ReadHalf<'_>,
    rsa: &RSA
) -> InitKey {
    let mut vec: Vec<u128> = Vec::new();

    for _i in 0..match init_key {
        InitKey::AES128(_) => 16,
        InitKey::AES192(_) => 24,
        InitKey::AES256(_) => 32,
    } {
        vec.push(rd.read_u128().await.expect("failed to read aes key"));
    }

    let vec = rsa.decrypt(vec);

    match init_key {
        InitKey::AES128(_) => InitKey::AES128(vec_to_array16(vec).unwrap()),
        InitKey::AES192(_) => InitKey::AES192(vec_to_array24(vec).unwrap()),
        InitKey::AES256(_) => InitKey::AES256(vec_to_array32(vec).unwrap()),
    }
}

pub async fn send_rsa_key(wr: &mut WriteHalf<'_>, rsa: &RSA) {
    wr.write_u128(rsa.n).await.unwrap();
    wr.write_u128(rsa.e).await.unwrap();
}

pub async fn recive_rsa_key(rd: &mut ReadHalf<'_>) -> RSA {
    let n = rd.read_u128().await.expect("failed to read n");
    let e = rd.read_u128().await.expect("failed to read e");

    RSA::from_num(n, e, 0)
}
