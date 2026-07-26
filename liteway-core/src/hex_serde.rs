macro_rules! make_hex_module {
    ($name:ident, $n:expr) => {
        pub mod $name {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(data: &[u8; $n], s: S) -> Result<S::Ok, S::Error> {
                let encoded = hex::encode(data);
                s.serialize_str(&encoded)
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $n], D::Error> {
                let s = <String as Deserialize>::deserialize(d)?;
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if bytes.len() != $n {
                    return Err(serde::de::Error::custom(format!(
                        "expected {} bytes, got {}",
                        $n,
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; $n];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            }
        }
    };
}

make_hex_module!(size_32, 32);
make_hex_module!(size_64, 64);
make_hex_module!(size_1184, 1184);
make_hex_module!(size_1952, 1952);
make_hex_module!(size_3309, 3309);
