//! Streaming SHA-256 so arbitrarily large files never need to fit in memory.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

pub fn sha256_reader(r: &mut dyn Read) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

pub fn sha256_file(p: &Path) -> std::io::Result<String> {
    sha256_reader(&mut std::fs::File::open(p)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_vectors() {
        assert_eq!(sha256_reader(&mut &b""[..]).unwrap(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_reader(&mut &b"abc"[..]).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn handles_data_larger_than_the_buffer() {
        let d = vec![0x61u8; 3 * 1024 * 1024 + 17];
        assert_eq!(sha256_reader(&mut &d[..]).unwrap(), hex::encode(Sha256::digest(&d)));
    }
}
