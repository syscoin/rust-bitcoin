// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Addresses
//!
//! Support for ordinary base58 Bitcoin addresses and private keys
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//! extern crate rand;
//! extern crate secp256k1;
//! extern crate bitcoin;
//!
//! use bitcoin::network::constants::Network;
//! use bitcoin::util::address::Address;
//! use secp256k1::Secp256k1;
//! use rand::thread_rng;
//!
//! fn main() {
//!     // Generate random key pair
//!     let s = Secp256k1::new();
//!     let (_, public_key) = s.generate_keypair(&mut thread_rng());
//!
//!     // Generate pay-to-pubkey-hash address
//!     let address = Address::p2pkh(&public_key, Network::Bitcoin);
//! }
//! ```

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin_hashes::{hash160, Hash};
use secp256k1::key::PublicKey;
use syscoin_bech32::{self, u5, WitnessProgram};

#[cfg(feature = "serde")]
use serde;

use blockdata::opcodes;
use blockdata::script;
use consensus::encode;
use network::constants::Network;
use util::base58;

/// The method used to produce an address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Payload {
    /// pay-to-pkhash address
    PubkeyHash(hash160::Hash),
    /// P2SH address
    ScriptHash(hash160::Hash),
    /// Segwit address
    WitnessProgram(WitnessProgram),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A Bitcoin address
pub struct Address {
    /// The type of the address
    pub payload: Payload,
    /// The network on which this address is usable
    pub network: Network,
}

impl Address {
    /// Creates a pay to (compressed) public key hash address from a public key
    /// This is the preferred non-witness type address
    #[inline]
    pub fn p2pkh(pk: &PublicKey, network: Network) -> Address {
        Address {
            network: network,
            payload: Payload::PubkeyHash(hash160::Hash::hash(&pk.serialize()[..])),
        }
    }

    /// Creates a pay to uncompressed public key hash address from a public key
    /// This address type is discouraged as it uses more space but otherwise equivalent to p2pkh
    /// therefore only adds ambiguity
    #[inline]
    pub fn p2upkh(pk: &PublicKey, network: Network) -> Address {
        Address {
            network: network,
            payload: Payload::PubkeyHash(hash160::Hash::hash(&pk.serialize_uncompressed()[..])),
        }
    }

    /// Creates a pay to script hash P2SH address from a script
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig these days.
    #[inline]
    pub fn p2sh(script: &script::Script, network: Network) -> Address {
        Address {
            network: network,
            payload: Payload::ScriptHash(hash160::Hash::hash(&script[..])),
        }
    }

    /// Create a witness pay to public key address from a public key
    /// This is the native segwit address type for an output redeemable with a single signature
    pub fn p2wpkh(pk: &PublicKey, network: Network) -> Address {
        Address {
            network: network,
            payload: Payload::WitnessProgram(
                // unwrap is safe as witness program is known to be correct as above
                WitnessProgram::new(
                    u5::try_from_u8(0).expect("0<32"),
                    hash160::Hash::hash(&pk.serialize()[..])[..].to_vec(),
                    Address::bech_network(network),
                )
                .unwrap(),
            ),
        }
    }

    /// Create a pay to script address that embeds a witness pay to public key
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients
    pub fn p2shwpkh(pk: &PublicKey, network: Network) -> Address {
        let builder = script::Builder::new()
            .push_int(0)
            .push_slice(&hash160::Hash::hash(&pk.serialize()[..])[..]);
        Address {
            network: network,
            payload: Payload::ScriptHash(hash160::Hash::hash(builder.into_script().as_bytes())),
        }
    }

    /// Create a witness pay to script hash address
    pub fn p2wsh(script: &script::Script, network: Network) -> Address {
        use bitcoin_hashes::sha256;
        use bitcoin_hashes::Hash;

        Address {
            network: network,
            payload: Payload::WitnessProgram(
                // unwrap is safe as witness program is known to be correct as above
                WitnessProgram::new(
                    u5::try_from_u8(0).expect("0<32"),
                    sha256::Hash::hash(&script[..])[..].to_vec(),
                    Address::bech_network(network),
                )
                .unwrap(),
            ),
        }
    }

    /// Create a pay to script address that embeds a witness pay to script hash address
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients
    pub fn p2shwsh(script: &script::Script, network: Network) -> Address {
        use bitcoin_hashes::hash160;
        use bitcoin_hashes::sha256;
        use bitcoin_hashes::Hash;

        let ws = script::Builder::new()
            .push_int(0)
            .push_slice(&sha256::Hash::hash(&script[..])[..])
            .into_script();

        Address {
            network: network,
            payload: Payload::ScriptHash(hash160::Hash::hash(&ws[..])),
        }
    }

    #[inline]
    /// convert Network to bech32 network (this should go away soon)
    fn bech_network(network: Network) -> syscoin_bech32::constants::Network {
        match network {
            Network::Bitcoin => syscoin_bech32::constants::Network::Syscoin,
            Network::Testnet => syscoin_bech32::constants::Network::SyscoinTestnet,
            Network::Regtest => syscoin_bech32::constants::Network::Regtest,
        }
    }

    /// Generates a script pubkey spending to this address
    pub fn script_pubkey(&self) -> script::Script {
        match self.payload {
            Payload::PubkeyHash(ref hash) => script::Builder::new()
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash[..])
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_CHECKSIG),
            Payload::ScriptHash(ref hash) => script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash[..])
                .push_opcode(opcodes::all::OP_EQUAL),
            Payload::WitnessProgram(ref witprog) => script::Builder::new()
                .push_int(witprog.version().to_u8() as i64)
                .push_slice(witprog.program()),
        }
        .into_script()
    }
}

impl Display for Address {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match self.payload {
            Payload::PubkeyHash(ref hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = match self.network {
                    Network::Bitcoin => 63,
                    Network::Testnet | Network::Regtest => 65,
                };
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::ScriptHash(ref hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = match self.network {
                    Network::Bitcoin => 5,
                    Network::Testnet | Network::Regtest => 196,
                };
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::WitnessProgram(ref witprog) => fmt.write_str(&witprog.to_address()),
        }
    }
}

impl FromStr for Address {
    type Err = encode::Error;

    fn from_str(s: &str) -> Result<Address, encode::Error> {
        // bech32 (note that upper or lowercase is allowed but NOT mixed case)
        if s.starts_with("sc1")
            || s.starts_with("SC1")
            || s.starts_with("ts1")
            || s.starts_with("TS1")
            || s.starts_with("scrt1")
            || s.starts_with("SCRT1")
        {
            let witprog = WitnessProgram::from_address(s)?;
            let network = match witprog.network() {
                syscoin_bech32::constants::Network::Syscoin => Network::Bitcoin,
                syscoin_bech32::constants::Network::SyscoinTestnet => Network::Testnet,
                syscoin_bech32::constants::Network::Regtest => Network::Regtest,
                _ => panic!("unknown network"),
            };
            if witprog.version().to_u8() != 0 {
                return Err(encode::Error::UnsupportedWitnessVersion(
                    witprog.version().to_u8(),
                ));
            }
            return Ok(Address {
                network: network,
                payload: Payload::WitnessProgram(witprog),
            });
        }

        if s.len() > 50 {
            return Err(encode::Error::Base58(base58::Error::InvalidLength(
                s.len() * 11 / 15,
            )));
        }

        // Base 58
        let data = base58::from_check(s)?;

        if data.len() != 21 {
            return Err(encode::Error::Base58(base58::Error::InvalidLength(
                data.len(),
            )));
        }

        let (network, payload) = match data[0] {
            63 => (
                Network::Bitcoin,
                Payload::PubkeyHash(hash160::Hash::from_slice(&data[1..]).unwrap()),
            ),
            5 => (
                Network::Bitcoin,
                Payload::ScriptHash(hash160::Hash::from_slice(&data[1..]).unwrap()),
            ),
            65 => (
                Network::Testnet,
                Payload::PubkeyHash(hash160::Hash::from_slice(&data[1..]).unwrap()),
            ),
            196 => (
                Network::Testnet,
                Payload::ScriptHash(hash160::Hash::from_slice(&data[1..]).unwrap()),
            ),
            x => {
                return Err(encode::Error::Base58(base58::Error::InvalidVersion(vec![
                    x,
                ])));
            }
        };

        Ok(Address {
            network: network,
            payload: payload,
        })
    }
}

impl ::std::fmt::Debug for Address {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Address {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::fmt::{self, Formatter};

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Address;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a Bitcoin address")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Address::from_str(v).map_err(E::custom)
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::string::ToString;

    use bitcoin_hashes::{hash160, Hash};
    use hex::decode as hex_decode;
    use secp256k1::key::PublicKey;

    use super::*;
    use blockdata::script::Script;
    use network::constants::Network::{Bitcoin, Testnet};

    macro_rules! hex (($hex:expr) => (hex_decode($hex).unwrap()));
    macro_rules! hex_key (($hex:expr) => (PublicKey::from_slice(&hex!($hex)).unwrap()));
    macro_rules! hex_script (($hex:expr) => (Script::from(hex!($hex))));
    macro_rules! hex_hash160 (($hex:expr) => (hash160::Hash::from_slice(&hex!($hex)).unwrap()));

    #[test]
    fn test_p2pkh_address_58() {
        let addr = Address {
            network: Bitcoin,
            payload: Payload::PubkeyHash(hex_hash160!("162c5ea71c0b23f5b9022ef047c4a86470a5b070")),
        };

        assert_eq!(
            addr.script_pubkey(),
            hex_script!("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        );
        assert_eq!(&addr.to_string(), "SPKF3vdccHNqLT6SsmAMvyvUvKKXVSLKkX");
        assert_eq!(
            Address::from_str("SPKF3vdccHNqLT6SsmAMvyvUvKKXVSLKkX").unwrap(),
            addr
        );
    }

    #[test]
    fn test_p2pkh_from_key() {
        let key = hex_key!("048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183");
        let addr = Address::p2upkh(&key, Bitcoin);
        assert_eq!(&addr.to_string(), "SkbVFqQzKNh27X6aSee43S7iRCFXy2pLxu");

        let key = hex_key!(&"03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f");
        let addr = Address::p2pkh(&key, Testnet);
        assert_eq!(&addr.to_string(), "TLCwwMZqhuLF7KZcnpWFwRVqQ3oBbbyudz");
    }

    #[test]
    fn test_p2sh_address_58() {
        let addr = Address {
            network: Bitcoin,
            payload: Payload::ScriptHash(hex_hash160!("162c5ea71c0b23f5b9022ef047c4a86470a5b070")),
        };

        assert_eq!(
            addr.script_pubkey(),
            hex_script!("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087")
        );
        assert_eq!(&addr.to_string(), "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k");
        assert_eq!(
            Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap(),
            addr
        );
    }

    #[test]
    fn test_p2sh_parse() {
        let script = hex_script!("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae");
        let addr = Address::p2sh(&script, Testnet);

        assert_eq!(&addr.to_string(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
        assert_eq!(
            Address::from_str("2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr").unwrap(),
            addr
        );
    }

    #[test]
    fn test_p2wpkh() {
        // stolen from Bitcoin transaction: b3c8c2b6cfc335abbcb2c7823a8453f55d64b2b5125a9a61e8737230cdb8ce20
        let key = hex_key!("033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc");
        let addr = Address::p2wpkh(&key, Bitcoin);
        assert_eq!(
            &addr.to_string(),
            "sc1qvzvkjn4q3nszqxrv3nraga2r822xjty398xhuq"
        );
    }

    #[test]
    fn test_p2wsh() {
        // stolen from Bitcoin transaction 5df912fda4becb1c29e928bec8d64d93e9ba8efa9b5b405bd683c86fd2c65667
        let script = hex_script!("52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae");
        let addr = Address::p2wsh(&script, Bitcoin);
        assert_eq!(
            &addr.to_string(),
            "sc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxslfwnwn"
        );
    }

    #[test]
    #[cfg(all(feature = "serde", feature = "strason"))]
    fn test_json_serialize() {
        use strason::Json;

        let addr = Address::from_str("SPKF3vdccHNqLT6SsmAMvyvUvKKXVSLKkX").unwrap();
        let json = Json::from_serialize(&addr).unwrap();
        assert_eq!(json.string(), Some("SPKF3vdccHNqLT6SsmAMvyvUvKKXVSLKkX"));
        let into: Address = json.into_deserialize().unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        );

        let addr = Address::from_str("SkbVFqQzKNh27X6aSee43S7iRCFXy2pLxu").unwrap();
        let json = Json::from_serialize(&addr).unwrap();
        assert_eq!(json.string(), Some("SkbVFqQzKNh27X6aSee43S7iRCFXy2pLxu"));
        let into: Address = json.into_deserialize().unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("76a914ff99864ce1a887e00c9c8615210d6267edd7d7a588ac")
        );



        let addr = Address::from_str("sc1q8fjfq7gjd6nma8lh4qxr9qxtj3yz5sg0vkr2tk").unwrap();
        let json = Json::from_serialize(&addr).unwrap();
        assert_eq!(
            json.string(),
            Some("sc1q8fjfq7gjd6nma8lh4qxr9qxtj3yz5sg0vkr2tk")
        );
        let into: Address = json.into_deserialize().unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("00143a649079126ea7be9ff7a80c3280cb94482a410f")
        );
    }
}
