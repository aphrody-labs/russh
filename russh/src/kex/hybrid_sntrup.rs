//! `sntrup761x25519-sha512` (and the `@openssh.com` alias): Streamlined NTRU Prime 761 combined
//! with X25519, as in OpenSSH `kexsntrup761x25519.c` and draft-josefsson-ntruprime-ssh.
//!
//! Wire format: the client sends `C_INIT = sntrup761 public key (1158) || X25519 public key (32)`,
//! the server answers `S_REPLY = sntrup761 ciphertext (1039) || X25519 public key (32)`.
//! The shared secret is `K = SHA-512(K_PQ || K_CL)`, encoded as an SSH string, and the exchange
//! hash uses SHA-512.

use byteorder::{BigEndian, ByteOrder};
use curve25519_dalek::montgomery::MontgomeryPoint;
use log::debug;
use sha2::Digest;
use ssh_encoding::{Encode, Writer};

use super::{compute_keys, KexAlgorithm, KexAlgorithmImplementor, KexType, SharedSecret};
use crate::mac;
use crate::session::Exchange;
use crate::{cipher, msg, CryptoVec, Error};

const SNTRUP761_PUBLIC_KEY_SIZE: usize = sntrup761::PUBLIC_KEY_SIZE;
const SNTRUP761_CIPHERTEXT_SIZE: usize = sntrup761::CIPHERTEXT_SIZE;
const X25519_PUBLIC_KEY_SIZE: usize = 32;

pub struct Sntrup761X25519KexType {}

impl KexType for Sntrup761X25519KexType {
    fn make(&self) -> KexAlgorithm {
        Sntrup761X25519Kex::default().into()
    }
}

#[doc(hidden)]
#[derive(Default)]
pub struct Sntrup761X25519Kex {
    pq_secret: Option<Box<sntrup761::DecapsulationKey>>,
    x25519_secret: Option<[u8; 32]>,
    k_pq: Option<[u8; sntrup761::SHARED_SECRET_SIZE]>,
    k_cl: Option<MontgomeryPoint>,
}

impl std::fmt::Debug for Sntrup761X25519Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Sntrup761X25519Kex {{ pq_secret: [hidden], x25519_secret: [hidden], k_pq: [hidden], k_cl: [hidden] }}",
        )
    }
}

impl Sntrup761X25519Kex {
    /// `SHA-512(K_PQ || K_CL)`.
    fn combined_secret(&self) -> Result<Vec<u8>, Error> {
        let k_pq = self.k_pq.as_ref().ok_or(Error::KexInit)?;
        let k_cl = self.k_cl.as_ref().ok_or(Error::KexInit)?;
        let mut hasher = sha2::Sha512::new();
        hasher.update(k_pq);
        hasher.update(k_cl.0);
        Ok(hasher.finalize().to_vec())
    }
}

impl KexAlgorithmImplementor for Sntrup761X25519Kex {
    fn skip_exchange(&self) -> bool {
        false
    }

    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), Error> {
        debug!("server_dh (hybrid sntrup761)");

        // SSH_MSG_KEX_ECDH_INIT shares the number of KEX_HYBRID_INIT (30).
        if payload.first() != Some(&msg::KEX_HYBRID_INIT) {
            return Err(Error::Inconsistent);
        }
        if payload.len() < 5 {
            return Err(Error::Inconsistent);
        }
        #[allow(clippy::indexing_slicing)]
        let c_init_len = BigEndian::read_u32(&payload[1..]) as usize;
        if payload.len() < 5 + c_init_len {
            return Err(Error::Inconsistent);
        }
        if c_init_len != SNTRUP761_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE {
            return Err(Error::Kex);
        }
        #[allow(clippy::indexing_slicing)]
        let c_init = &payload[5..5 + c_init_len];
        #[allow(clippy::indexing_slicing)]
        let (c_pq_bytes, c_cl_bytes) = c_init.split_at(SNTRUP761_PUBLIC_KEY_SIZE);

        let c_pq = sntrup761::EncapsulationKey::try_from(c_pq_bytes).map_err(|_| Error::Kex)?;
        let (s_ct, k_pq) = c_pq.encapsulate(rand::rng());

        let mut c_pk1 = MontgomeryPoint([0; 32]);
        c_pk1.0.copy_from_slice(c_cl_bytes);
        let s_secret = rand::random::<[u8; 32]>();
        let s_pk1 = MontgomeryPoint::mul_base_clamped(s_secret);
        let k_cl = c_pk1.mul_clamped(s_secret);
        if k_cl.0 == [0u8; 32] {
            debug!("client sent a low-order curve25519 pubkey");
            return Err(Error::Kex);
        }

        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend_from_slice(s_ct.as_ref());
        exchange.server_ephemeral.extend_from_slice(&s_pk1.0);

        let mut pq = [0u8; sntrup761::SHARED_SECRET_SIZE];
        pq.copy_from_slice(k_pq.as_ref());
        self.k_pq = Some(pq);
        self.k_cl = Some(k_cl);
        Ok(())
    }

    fn client_dh(
        &mut self,
        client_ephemeral: &mut Vec<u8>,
        writer: &mut impl Writer,
    ) -> Result<(), Error> {
        let (pq_pk, pq_sk) = sntrup761::generate_key(rand::rng());
        let x25519_secret = rand::random::<[u8; 32]>();
        let x25519_pk = MontgomeryPoint::mul_base_clamped(x25519_secret);

        client_ephemeral.clear();
        client_ephemeral.extend_from_slice(pq_pk.as_ref());
        client_ephemeral.extend_from_slice(&x25519_pk.0);

        msg::KEX_HYBRID_INIT.encode(writer)?;
        client_ephemeral.as_slice().encode(writer)?;

        self.pq_secret = Some(Box::new(pq_sk));
        self.x25519_secret = Some(x25519_secret);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), Error> {
        if remote_pubkey_.len() != SNTRUP761_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE {
            return Err(Error::Kex);
        }
        let (s_ct_bytes, s_cl_bytes) = remote_pubkey_.split_at(SNTRUP761_CIPHERTEXT_SIZE);
        let s_ct = sntrup761::Ciphertext::try_from(s_ct_bytes).map_err(|_| Error::KexInit)?;

        let pq_secret = self.pq_secret.take().ok_or(Error::KexInit)?;
        let k_pq = pq_secret.decapsulate(&s_ct);

        let mut s_pk1 = MontgomeryPoint([0; 32]);
        s_pk1.0.copy_from_slice(s_cl_bytes);
        let x25519_secret = self.x25519_secret.take().ok_or(Error::KexInit)?;
        let k_cl = s_pk1.mul_clamped(x25519_secret);
        if k_cl.0 == [0u8; 32] {
            debug!("server sent a low-order curve25519 pubkey");
            return Err(Error::Kex);
        }

        let mut pq = [0u8; sntrup761::SHARED_SECRET_SIZE];
        pq.copy_from_slice(k_pq.as_ref());
        self.k_pq = Some(pq);
        self.k_cl = Some(k_cl);
        Ok(())
    }

    fn shared_secret_bytes(&self) -> Option<&[u8]> {
        // The hybrid secret is derived in compute_keys; expose the X25519 part, as the
        // ML-KEM implementation does.
        self.k_cl.as_ref().map(|k| k.0.as_slice())
    }

    fn compute_exchange_hash(
        &self,
        key: &[u8],
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<Vec<u8>, Error> {
        buffer.clear();
        exchange.client_id.encode(buffer)?;
        exchange.server_id.encode(buffer)?;
        exchange.client_kex_init.encode(buffer)?;
        exchange.server_kex_init.encode(buffer)?;
        buffer.extend(key);
        exchange.client_ephemeral.encode(buffer)?;
        exchange.server_ephemeral.encode(buffer)?;
        self.combined_secret()?.as_slice().encode(buffer)?;

        let mut hasher = sha2::Sha512::new();
        hasher.update(&buffer);
        Ok(hasher.finalize().to_vec())
    }

    fn compute_keys(
        &self,
        session_id: &[u8],
        exchange_hash: &[u8],
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, Error> {
        let shared_secret = SharedSecret::from_string(&self.combined_secret()?)?;
        compute_keys::<sha2::Sha512>(
            Some(&shared_secret),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_and_server_agree() {
        let mut client = Sntrup761X25519Kex::default();
        let mut server = Sntrup761X25519Kex::default();
        let mut client_ephemeral = Vec::new();
        let mut init = Vec::new();
        client.client_dh(&mut client_ephemeral, &mut init).unwrap();
        assert_eq!(client_ephemeral.len(), SNTRUP761_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE);

        let mut exchange = Exchange {
            client_id: b"SSH-2.0-Test_Client".to_vec(),
            server_id: b"SSH-2.0-Test_Server".to_vec(),
            client_kex_init: bytes::Bytes::from_static(b"client_kex_init"),
            server_kex_init: bytes::Bytes::from_static(b"server_kex_init"),
            client_ephemeral: client_ephemeral.clone(),
            server_ephemeral: Vec::new(),
            gex: None,
        };
        server.server_dh(&mut exchange, &init).unwrap();
        assert_eq!(
            exchange.server_ephemeral.len(),
            SNTRUP761_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE
        );
        client.compute_shared_secret(&exchange.server_ephemeral).unwrap();

        assert_eq!(client.k_pq, server.k_pq);
        assert_eq!(client.k_cl.unwrap().0, server.k_cl.unwrap().0);
        let mut buf = CryptoVec::new();
        let h1 = client.compute_exchange_hash(b"hostkey", &exchange, &mut buf).unwrap();
        let h2 = server.compute_exchange_hash(b"hostkey", &exchange, &mut buf).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn rejects_bad_lengths() {
        let mut client = Sntrup761X25519Kex::default();
        let mut eph = Vec::new();
        let mut init = Vec::new();
        client.client_dh(&mut eph, &mut init).unwrap();
        assert!(client.compute_shared_secret(&[0u8; 100]).is_err());

        let mut server = Sntrup761X25519Kex::default();
        let mut exchange = Exchange::default();
        let mut short = vec![msg::KEX_HYBRID_INIT];
        short.extend_from_slice(&10u32.to_be_bytes());
        short.extend_from_slice(&[0u8; 10]);
        assert!(server.server_dh(&mut exchange, &short).is_err());
    }
}
