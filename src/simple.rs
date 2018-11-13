
extern crate clear_on_drop;

use std::ptr;
use rand::Rng;
use tiny_keccak::Keccak;

use params::{
    N, Q,
    POLY_BYTES,
    SEEDBYTES, RECBYTES,
    SENDABYTES, SENDBBYTES
};
use poly::{poly_tobytes, poly_frombytes, uniform, noise, pointwise, ntt, add, get_noise,
           invntt};
use poly_simple::{compress, decompress, memwipe, sub, to_msg};

pub const HIGH_BYTES: usize = 384;
pub const SEND_A_SIMPLE_SIZE: usize = POLY_BYTES + SEEDBYTES;
pub const SEND_B_SIMPLE_SIZE: usize = POLY_BYTES + HIGH_BYTES;


fn encode_b_simple(r: &mut [u8], b: &[u16; N], v: &[u16; N]) {
    poly_tobytes(b, r);
    compress(&mut r[POLY_BYTES..], v);
}

fn decode_b_simple(b: &mut [u16; N], v: &mut [u16; N], r: &[u8]) -> Vec<u8> {
    poly_frombytes(r, b);
    let r_clone = decompress(&r[POLY_BYTES..], v);
    r_clone
}

fn encode_a(r: &mut [u8], pk: &[u16; N], seed: &[u8; SEEDBYTES]) {
    poly_tobytes(pk, r);
    for i in 0..SEEDBYTES {
        r[POLY_BYTES+i] = seed[i];
    }
}

fn decode_a(pk: &mut [u16; N], seed: &mut [u8; SEEDBYTES], r: &[u8]) {
    poly_frombytes(r, pk);
    for i in 0..seed.len() {
        seed[i] = r[POLY_BYTES+i];
    }
}

/// Alice's NewHope-Simple public key.
pub struct PublicKeySimpleAlice {
    send: [u8; SEND_A_SIMPLE_SIZE],
}

/// Alice's NewHope-Simple private key.
pub struct PrivateKeySimpleAlice {
    sk: [u16; N],
}

/// returns a NewHope-Simple private/public key pair.
pub fn generate_keypair_simple_alice<R: Rng>(mut rng: R) -> (PrivateKeySimpleAlice, PublicKeySimpleAlice) {
    let (mut a, mut e, mut pk, mut r) = ([0; N], [0; N], [0; N], [0; N]);
    let (mut seed, mut noise_seed) = ([0u8; SEEDBYTES], [0u8; SEEDBYTES]);
    let mut sha3 = Keccak::new_sha3_256();

    rng.fill_bytes(&mut seed);
    sha3.update(&seed);
    sha3.finalize(&mut seed);
    uniform(&mut a, &seed);

    rng.fill_bytes(&mut noise_seed);

    let mut sk = [0u16; N];
    noise(&mut sk, &mut rng);
    ntt(&mut sk);
    let priv_key = PrivateKeySimpleAlice{
        sk: sk,
    };

    let mut pk = [0u16; N];
    noise(&mut e, &mut rng);
    ntt(&mut e);
    pointwise(&mut r, &priv_key.sk, &a);
    add(&mut pk, &e, &r);

    let mut send = [0u8; SEND_A_SIMPLE_SIZE];
    encode_a(&mut send, &pk, &seed);
    let pub_key = PublicKeySimpleAlice{
        send: send,
    };

    memwipe(&mut noise_seed);
    return (priv_key, pub_key);
}

pub struct PublicKeySimpleBob {
    send: [u8; SEND_B_SIMPLE_SIZE],
}

/// this is the responder side of the NewHope-Simple key exchange
pub fn key_exchange_simple_bob<R: Rng>(mut rng: R, alice_pub_key: &PublicKeySimpleAlice) -> (PublicKeySimpleBob, Vec<u8>) {
    let (mut pka, mut a, mut sp, mut ep) = ([0u16; N], [0u16; N], [0u16; N], [0u16; N]);
    let (mut bp, mut v, mut epp, mut m) = ([0u16; N], [0u16; N], [0u16; N], [0u16; N]);
    let (mut seed, mut noise_seed) = ([0u8; SEEDBYTES], [0u8; SEEDBYTES]);
    let mut sha3 = Keccak::new_sha3_256();

    rng.fill_bytes(&mut noise_seed);

    let mut shared_key = [0u8; SENDABYTES];
    rng.fill_bytes(&mut shared_key);
    sha3.update(&shared_key);
    sha3.finalize(&mut shared_key);
    poly_frombytes(&shared_key, &mut m);

    decode_a(&mut pka, &mut seed, &alice_pub_key.send);
    uniform(&mut a, &seed);

    get_noise(&mut sp, &mut noise_seed, 0);
    ntt(&mut sp);
    get_noise(&mut ep, &mut noise_seed, 1);
    ntt(&mut ep);

    pointwise(&mut bp, &a, &sp);
    let bp_clone = bp.clone();
    add(&mut bp, &bp_clone, &ep);

    pointwise(&mut v, &pka, &sp);
    invntt(&mut v);

    get_noise(&mut epp, &mut noise_seed, 2);
    let mut v_clone = v.clone();
    add(&mut v, &v_clone, &epp);
    v_clone = v.clone();
    add(&mut v, &v_clone, &m);

    let mut send = [0u8; SEND_B_SIMPLE_SIZE];
    encode_b_simple(&mut send, &bp, &v);
    let pub_key = PublicKeySimpleBob{
        send: send,
    };
    let mut sha3 = Keccak::new_sha3_256();
    sha3.update(&shared_key);
    let mut mu = vec![0u8; 32];
    sha3.finalize(&mut mu);

    memwipe(&mut noise_seed);
    memwipe(&mut shared_key);
    (pub_key, mu)
}

pub fn key_exchange_simple_alice(pub_public_key: &mut PublicKeySimpleBob, alice_secret_key: &PrivateKeySimpleAlice) -> Vec<u8> {
    let (mut v, mut bp, mut k) = ([0u16; N], [0u16; N], [0u16; N]);

    let send = decode_b_simple(&mut bp, &mut v, &pub_public_key.send);
    pointwise(&mut k, &alice_secret_key.sk, &bp);
    invntt(&mut k);

    let k_clone = k.clone();
    sub(&mut k, &k_clone, &v);

    let mut shared_key = [0u8; SEEDBYTES];
    to_msg(&mut shared_key, &k);

    let mut sha3 = Keccak::new_sha3_256();
    sha3.update(&shared_key);
    let mut mu = vec![0u8; 32];
    sha3.finalize(&mut mu);

    memwipe(&mut shared_key);

    mu
}


#[cfg(test)]
mod tests {

    use super::super::params::N;
    use super::encode_b_simple;

    #[test]
    fn encode_b_simple_test() {
        let mut r = vec![0u8; 2000];
        let b = [0u16; N];
        let v = [0u16; N];
        //encode_b_simple(&mut r, &b, &v);
    }
}
