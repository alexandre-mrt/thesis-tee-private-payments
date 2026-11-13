use std::time::{Duration, Instant};

use anyhow::Result;
use pt_tee::channel::{EnclaveKeypair, Sealed};
use tv_client::seal_to;
use tv_core::{
    Bytes32, LogEntry, OpKind, Opening, PayPublic, PaySecret, Receive, SealedBlob, Seed, SideKind,
    Signature, SigningKey, VerifyingKey, commitment, decode_cbor, derive_sk, encode_cbor,
    random_bytes32, sign_digest, verify_digest,
};

fn time<T>(iterations: usize, mut op: impl FnMut() -> T) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(op());
    }
    start.elapsed().div_f64(iterations.max(1) as f64)
}

struct Fixtures {
    key: SigningKey,
    pk: Bytes32,
    digest: Bytes32,
    sig: Signature,
    parsed: VerifyingKey,
    enclave_key: EnclaveKeypair,
    channel_pk: [u8; 32],
    secret: PaySecret,
    blob: SealedBlob,
    receive_bytes: Vec<u8>,
    entry: LogEntry,
    seed: Seed,
}

fn sample_receive(f: &SignedFixture) -> Receive {
    Receive {
        channel_pk: f.channel_pk,
        public: PayPublic {
            pk_a: f.pk,
            com_a_next: f.digest,
            sig_a: f.sig,
            pk_b: f.pk,
            com_b_next: f.digest,
            sig_b: f.sig,
        },
        payer: f.blob.clone(),
        payee: f.blob.clone(),
    }
}

struct SignedFixture {
    pk: Bytes32,
    digest: Bytes32,
    sig: Signature,
    channel_pk: [u8; 32],
    blob: SealedBlob,
}

fn sample_secret(next_pk: Bytes32, sig: Signature) -> PaySecret {
    PaySecret {
        v: 1,
        opening: Opening {
            balance: 1,
            r: random_bytes32(),
            sig,
            side: SideKind::User,
            next_pk,
            next_r: random_bytes32(),
        },
    }
}

fn fixtures() -> Result<Fixtures> {
    let key = SigningKey::generate();
    let pk = key.public_key();
    let digest = random_bytes32();
    let sig = sign_digest(&key, &digest);
    let enclave_key = EnclaveKeypair::generate();
    let channel_pk = enclave_key.public_key();
    let secret = sample_secret(pk, sig);
    let blob = seal_to(&channel_pk, &secret)?;
    let signed = SignedFixture {
        pk,
        digest,
        sig,
        channel_pk,
        blob,
    };
    let receive_bytes = encode_cbor(&sample_receive(&signed))?;
    let entry = LogEntry {
        seq: 0,
        kind: OpKind::Pay,
        serials: vec![pk, pk],
        commitments: vec![digest, digest],
        sigs: vec![sig, sig],
        digest,
    };
    Ok(Fixtures {
        parsed: VerifyingKey::parse(&pk)?,
        key,
        pk,
        digest,
        sig,
        enclave_key,
        channel_pk,
        secret,
        blob: signed.blob,
        receive_bytes,
        entry,
        seed: Seed::generate(),
    })
}

fn signature_costs(f: &Fixtures, n: usize) -> Vec<(&'static str, Duration)> {
    vec![
        (
            "ed25519 sign digest",
            time(n, || sign_digest(&f.key, &f.digest)),
        ),
        (
            "ed25519 verify_strict, key parsed per call",
            time(n, || verify_digest(&f.pk, &f.digest, &f.sig)),
        ),
        (
            "ed25519 verify_strict, parsed key reused",
            time(n, || f.parsed.verify_digest(&f.digest, &f.sig)),
        ),
        (
            "ed25519 VerifyingKey::parse",
            time(n, || VerifyingKey::parse(&f.pk)),
        ),
    ]
}

fn channel_costs(f: &Fixtures, n: usize) -> Vec<(&'static str, Duration)> {
    vec![
        (
            "x25519 accept + open 2 KiB blob + decode PaySecret",
            time(n, || -> Result<PaySecret> {
                let channel = f.enclave_key.accept(&f.blob.client_pk)?;
                let plaintext = channel.open_request(&Sealed {
                    nonce: f.blob.nonce,
                    ciphertext: f.blob.ciphertext.clone(),
                })?;
                Ok(decode_cbor(&plaintext)?)
            }),
        ),
        (
            "client seal PaySecret (x25519 keygen + hkdf + chacha20poly1305)",
            time(n, || seal_to(&f.channel_pk, &f.secret)),
        ),
        (
            "x25519 EnclaveKeypair::generate (per attest)",
            time(n, EnclaveKeypair::generate),
        ),
    ]
}

fn hashing_and_encoding_costs(f: &Fixtures, n: usize) -> Vec<(&'static str, Duration)> {
    vec![
        (
            "sha256 commitment",
            time(n, || commitment(1, &f.pk, &f.digest)),
        ),
        (
            "hkdf derive_sk + public key",
            time(n, || derive_sk(&f.seed, 1).map(|k| k.public_key())),
        ),
        (
            "cbor decode Receive",
            time(n, || decode_cbor::<Receive>(&f.receive_bytes)),
        ),
        (
            "json encode LogEntry (Pay)",
            time(n, || serde_json::to_vec(&f.entry)),
        ),
    ]
}

pub fn primitives(iterations: usize) -> Result<Vec<(&'static str, Duration)>> {
    let f = fixtures()?;
    let mut out = signature_costs(&f, iterations);
    out.extend(channel_costs(&f, iterations));
    out.extend(hashing_and_encoding_costs(&f, iterations));
    Ok(out)
}
