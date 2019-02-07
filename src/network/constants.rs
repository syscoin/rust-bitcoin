// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Network constants
//!
//! This module provides various constants relating to the Bitcoin network
//! protocol, such as protocol versioning and magic header bytes.
//!
//! The [`Network`][1] type implements the [`Decodable`][2] and
//! [`Encodable`][3] traits and encodes the magic bytes of the given
//! network
//!
//! [1]: enum.Network.html
//! [2]: ../../consensus/encode/trait.Decodable.html
//! [3]: ../../consensus/encode/trait.Encodable.html
//!
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use bitcoin::network::constants::Network;
//! use bitcoin::consensus::encode::serialize;
//!
//! let network = Network::Bitcoin;
//! let bytes = serialize(&network);
//!
//! assert_eq!(&bytes[..], &[0xCE, 0xE2, 0xCA, 0xFF]);
//! ```

use consensus::encode::{Decodable, Encodable};
use consensus::encode::{self, Encoder, Decoder};

/// Version of the protocol as appearing in network message headers
pub const PROTOCOL_VERSION: u32 = 70400;
/// Bitfield of services provided by this node
pub const SERVICES: u64 = 0;
/// User agent as it appears in the version message
pub const USER_AGENT: &'static str = "syscoin-rust v0.1";

user_enum! {
    /// The cryptocurrency to act on
    #[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
    pub enum Network {
        /// Classic Bitcoin
        Bitcoin <-> "syscoin",
        /// Bitcoin's testnet
        Testnet <-> "syscointestnet",
        /// Bitcoin's regtest
        Regtest <-> "regtest"
    }
}

impl Network {
    /// Creates a `Network` from the magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::network::constants::Network;
    ///
    /// assert_eq!(Some(Network::Bitcoin), Network::from_magic(0xFFCAE2CE));
    /// assert_eq!(None, Network::from_magic(0xFFFFFFFF));
    /// ```
    pub fn from_magic(magic: u32) -> Option<Network> {
        // Note: any new entries here must be added to `magic` below
        match magic {
            0xFFCAE2CE => Some(Network::Bitcoin),
            0xFECAE2CE => Some(Network::Testnet),
            0xDAB5BFFA => Some(Network::Regtest),
            _ => None
        }
    }

    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::network::constants::Network;
    ///
    /// let network = Network::Bitcoin;
    /// assert_eq!(network.magic(), 0xFFCAE2CE);
    /// ```
    pub fn magic(&self) -> u32 {
        // Note: any new entries here must be added to `from_magic` above
        match *self {
            Network::Bitcoin => 0xFFCAE2CE,
            Network::Testnet => 0xFECAE2CE,
            Network::Regtest => 0xDAB5BFFA,
        }
    }
}

impl<S: Encoder> Encodable<S> for Network {
    /// Encodes the magic bytes of `Network`.
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.magic().consensus_encode(s)
    }
}

impl<D: Decoder> Decodable<D> for Network {
    /// Decodes the magic bytes of `Network`.
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Network, encode::Error> {
        u32::consensus_decode(d)
            .and_then(|m| {
                Network::from_magic(m)
                    .ok_or(encode::Error::UnknownNetworkMagic(m))
            })
    }
}

#[cfg(test)]
mod tests {
  use super::Network;
  use consensus::encode::{deserialize, serialize};

  #[test]
  fn serialize_test() {
    assert_eq!(serialize(&Network::Bitcoin), vec![0xce, 0xe2, 0xca, 0xff]);
    assert_eq!(serialize(&Network::Testnet), vec![0xce, 0xe2, 0xca, 0xfe]);
    assert_eq!(serialize(&Network::Regtest), vec![0xfa, 0xbf, 0xb5, 0xda]);

    assert_eq!(deserialize(&[0xce, 0xe2, 0xca, 0xff]).ok(), Some(Network::Bitcoin));
    assert_eq!(deserialize(&[0xce, 0xe2, 0xca, 0xfe]).ok(), Some(Network::Testnet));
    assert_eq!(deserialize(&[0xfa, 0xbf, 0xb5, 0xda]).ok(), Some(Network::Regtest));

    let bad: Result<Network, _> = deserialize("fakenet".as_bytes());
    assert!(bad.is_err());
  }

  #[test]
  fn string_test() {
      assert_eq!(Network::Bitcoin.to_string(), "syscoin");
      assert_eq!(Network::Testnet.to_string(), "syscointestnet");
      assert_eq!(Network::Regtest.to_string(), "regtest");

      assert_eq!("syscoin".parse::<Network>().unwrap(), Network::Bitcoin);
      assert_eq!("syscointestnet".parse::<Network>().unwrap(), Network::Testnet);
      assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
      assert!("fakenet".parse::<Network>().is_err());
  }
}

