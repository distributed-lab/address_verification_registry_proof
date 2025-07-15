use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

use risc0_zkvm::guest::env;

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GuestOutputs {
    p2pkh_address: String,
    arbitrary_bytes: Vec<u8>,
    pq_addresses: Vec<String>,
}

fn main() {
    let pk_bytes: Vec<u8> = env::read();
    let arbitrary_bytes: Vec<u8> = env::read();
    let pq_addresses: Vec<String> = env::read();
    let bitcoin_version_byte: u8 = env::read();
    let sig_bytes: Vec<u8> = env::read();

    let msg = build_sig_msg(&arbitrary_bytes, &pq_addresses);

    if !verify_signature(&msg, &sig_bytes, &pk_bytes) {
        panic!("Signature verification failed");
    }

    let p2pkh_address = compute_p2pkh(bitcoin_version_byte, &pk_bytes);

    let outputs = GuestOutputs {
        p2pkh_address,
        arbitrary_bytes,
        pq_addresses,
    };

    env::commit(&outputs);
}

fn build_sig_msg(arbitrary_bytes: &[u8], pq_addresses: &[String]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&arbitrary_bytes);
    for address in pq_addresses {
        msg.extend_from_slice(address.as_bytes());
    }

    msg
}

pub fn verify_signature(msg: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> bool {
    // Hash the message
    let msg_hash = Sha256::digest(msg);

    let msg_to_simplay: Vec<u8> = msg_hash.to_vec();

    println!("Message to verify: {}", hex::encode(&msg_to_simplay));

    let mut uncompressed_pk = vec![0x04];
    uncompressed_pk.extend_from_slice(pk_bytes);

    let encoded_point_pk = k256::EncodedPoint::from_bytes(&uncompressed_pk)
        .expect("Failed to create encoded point from public key bytes");

    // Parse public key
    let verifying_key = match VerifyingKey::from_encoded_point(&encoded_point_pk) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Parse signature
    let signature = match Signature::from_bytes(sig_bytes.into()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    verifying_key.verify(&msg_hash, &signature).is_ok()
}

fn compute_p2pkh(version_byte: u8, pk_bytes: &[u8]) -> String {
    let sha256_hash = hash::<Sha256>(&pk_bytes);
    let ripemd160_hash = hash::<Ripemd160>(&sha256_hash);

    let mut address = vec![version_byte];
    address.extend(ripemd160_hash);

    let checksum = hash::<Sha256>(&hash::<Sha256>(&address));
    address.extend_from_slice(&checksum[..4]);

    return bs58::encode(address).into_string();
}

fn hash<H>(bytes: &[u8]) -> Vec<u8>
where
    H: Digest + Default,
{
    let mut hasher = H::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use ripemd::Ripemd160;

    #[test]
    fn test_hash() {
        let data = b"Hello, world!";

        let sha256_hash = super::hash::<Ripemd160>(data);

        println!("SHA256: {}", hex::encode(&sha256_hash));
    }
}
