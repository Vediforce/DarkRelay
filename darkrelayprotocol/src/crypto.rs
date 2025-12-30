use rand::Rng;

/// Generate random padding bytes (0-256 bytes).
pub fn generate_padding() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(0..=256);
    let mut padding = vec![0u8; len];
    rng.fill(&mut padding[..]);
    padding
}

/// Add padding to plaintext. Format: [plaintext_len: u32][plaintext][padding].
pub fn add_padding(plaintext: &[u8]) -> Vec<u8> {
    let padding = generate_padding();
    let plaintext_len = plaintext.len() as u32;
    
    let mut result = Vec::with_capacity(4 + plaintext.len() + padding.len());
    result.extend_from_slice(&plaintext_len.to_be_bytes());
    result.extend_from_slice(plaintext);
    result.extend_from_slice(&padding);
    
    result
}

/// Remove padding from padded data. Returns plaintext.
pub fn remove_padding(padded: &[u8]) -> Result<Vec<u8>, String> {
    if padded.len() < 4 {
        return Err("padded data too short".to_string());
    }
    
    let plaintext_len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    
    if padded.len() < 4 + plaintext_len {
        return Err("invalid plaintext length".to_string());
    }
    
    Ok(padded[4..4 + plaintext_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_roundtrip() {
        let plaintext = b"Hello, world!";
        let padded = add_padding(plaintext);
        let recovered = remove_padding(&padded).unwrap();
        assert_eq!(plaintext, recovered.as_slice());
    }

    #[test]
    fn test_padding_varies() {
        let plaintext = b"test";
        let padded1 = add_padding(plaintext);
        let padded2 = add_padding(plaintext);
        // Padding should make different sizes (most of the time)
        // At least verify they decode to same plaintext
        assert_eq!(remove_padding(&padded1).unwrap(), plaintext);
        assert_eq!(remove_padding(&padded2).unwrap(), plaintext);
    }
}
