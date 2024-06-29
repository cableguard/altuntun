#[derive(Debug)]
pub(crate) struct KeyBytes(pub [u8; 32]);

// ATT: I can't see how this improves the handling for keys,
// strong candidate for removal

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    // From Hex or base64 to KeyBytes ~ [u8; 32]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                // Try to parse as Hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| "Error: Illegal character in key")?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                if let Ok(decoded_key) = base64::decode(s) {
                    if decoded_key.len() == internal.len() {
                        internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err("Error: Illegal character in key");
                    }
                }
            }
            _ => return Err("Error: Illegal key size"),
        }

        Ok(KeyBytes(internal))
    }
}
