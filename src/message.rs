use std::net;
use std::io;
use fixed::types::extra::U7;
use fixed::FixedU64;
pub use consensus_encode::{Error, Decodable, Encodable, deserialize, deserialize_partial, serialize, serialize_hex, MAX_VEC_SIZE};
use consensus_encode::impl_consensus_encoding;

macro_rules! impl_pure_encodable{
    ($ty:ident, $meth_dec:ident, $meth_enc:ident) => (
        impl Decodable for $ty {
            #[inline]
            fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
                Ok($ty::$meth_dec(Decodable::consensus_decode(d)?))
            }
        }
        impl Encodable for $ty {
            #[inline]
            fn consensus_encode<S: io::Write>(
                &self,
                s: S,
            ) -> Result<usize, io::Error> {
                Encodable::consensus_encode(&self.$meth_enc(), s)
            }
        }
    )
}

macro_rules! impl_option_encodable{
    ($ty:ident, $meth_dec:ident, $meth_enc:ident, $err:literal) => (
        impl Decodable for $ty {
            #[inline]
            fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
                $ty::$meth_dec(Decodable::consensus_decode(d)?).ok_or(Error::ParseFailed($err))
            }
        }
        impl Encodable for $ty {
            #[inline]
            fn consensus_encode<S: io::Write>(
                &self,
                s: S,
            ) -> Result<usize, io::Error> {
                Encodable::consensus_encode(&self.$meth_enc(), s)
            }
        }
    )
}

/// Currencies that protocol aware of, there can be currencies that will never be implemented but
/// index in protocol is known.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Currency {
    Btc,
    TBtc,
    Ergo,
    TErgo,
    UsdtOmni,
    TUsdtOmni,
    Ltc,
    TLtc,
    Zec,
    TZec,
    Cpr,
    TCpr,
    Dash,
    TDash,
}

impl Currency {
    pub fn to_index(&self) -> u32 {
        match self {
            Currency::Btc => 0,
            Currency::TBtc => 1,
            Currency::Ergo => 2,
            Currency::TErgo => 3,
            Currency::UsdtOmni => 4,
            Currency::TUsdtOmni => 5,
            Currency::Ltc => 6,
            Currency::TLtc => 7,
            Currency::Zec => 8,
            Currency::TZec => 9,
            Currency::Cpr => 10,
            Currency::TCpr => 11,
            Currency::Dash => 12,
            Currency::TDash => 13,
        }
    }

    pub fn from_index(i: u32) -> Option<Self> {
        match i {
            0 => Some(Currency::Btc),
            1 => Some(Currency::TBtc),
            2 => Some(Currency::Ergo),
            3 => Some(Currency::TErgo),
            4 => Some(Currency::UsdtOmni),
            5 => Some(Currency::TUsdtOmni),
            6 => Some(Currency::Ltc),
            7 => Some(Currency::TLtc),
            8 => Some(Currency::Zec),
            9 => Some(Currency::TZec),
            10 => Some(Currency::Cpr),
            11 => Some(Currency::TCpr),
            12 => Some(Currency::Dash),
            13 => Some(Currency::TDash),
            _ => None,
        }
    }
}
impl_option_encodable!(Currency, from_index, to_index, "Unknown currency");


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fiat {
    Usd,
    Eur,
    Rub,
}

impl Fiat {
    pub fn to_index(&self) -> u32 {
        match self {
            Fiat::Usd => 0,
            Fiat::Eur => 1,
            Fiat::Rub => 2,
        }
    }

    pub fn from_index(i: u32) -> Option<Self> {
        match i {
            0 => Some(Fiat::Usd),
            1 => Some(Fiat::Eur),
            2 => Some(Fiat::Rub),
            _ => None,
        }
    }
}
impl_option_encodable!(Fiat, from_index, to_index, "Unknown fiat");

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Address {
    Ipv4(net::SocketAddrV4),
    Ipv6(net::SocketAddrV6),
}

fn ipv6_to_be(addr: [u16; 8]) -> [u16; 8] {
    [addr[0].to_be(), addr[1].to_be(), addr[2].to_be(), addr[3].to_be(),
     addr[4].to_be(), addr[5].to_be(), addr[6].to_be(), addr[7].to_be()]
}

impl Decodable for Address {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let t: u8 = Decodable::consensus_decode(&mut d)?;
        let p: u16 = Decodable::consensus_decode(&mut d)?;
        match t {
            0 => {
                let b: [u8; 4] = Decodable::consensus_decode(d)?;
                let ip = net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                let addr = net::SocketAddrV4::new(ip, p);
                Ok(Address::Ipv4(addr))
            }
            1 => {
                let b: [u16; 8] = ipv6_to_be(Decodable::consensus_decode(d)?);
                let ip = net::Ipv6Addr::new(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
                let addr = net::SocketAddrV6::new(ip, p, 0, 0);
                Ok(Address::Ipv6(addr))
            }
            _ => Err(Error::ParseFailed("Unknown address type")),
        }
    }
}
impl Encodable for Address {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        match self {
            Address::Ipv4(sock) => {
                let t: u8 = 0;
                let l = Encodable::consensus_encode(&t, &mut s)?
                    + Encodable::consensus_encode(&sock.port(), &mut s)?
                    + Encodable::consensus_encode(&sock.ip().octets(), s)?;
                Ok(l)
            },
            Address::Ipv6(sock) => {
                let t: u8 = 1;
                let l = Encodable::consensus_encode(&t, &mut s)?
                    + Encodable::consensus_encode(&sock.port(), &mut s)?
                    + Encodable::consensus_encode(&sock.ip().octets(), s)?;
                Ok(l)
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Version {
    major: u16, // used only 10 bits
    minor: u16,
    patch: u16,
}

impl Version {
    /// Pack version as 32 bit word with 10 bits per component and 2 reserved bits.
    pub fn pack(&self) -> u32 {
        (((self.major & 0b000001111111111) as u32) <<  2) +
        (((self.minor & 0b000001111111111) as u32) << 12) +
        (((self.patch & 0b000001111111111) as u32) << 22)
    }

    /// Unpack version from 32 bit word with 10 bits per component and 2 reserved bits.
    pub fn unpack(w: u32) -> Self {
        Version {
            major: ((w >>  2) & 0b000001111111111) as u16,
            minor: ((w >> 12) & 0b000001111111111) as u16,
            patch: ((w >> 22) & 0b000001111111111) as u16,
        }
    }
}
impl_pure_encodable!(Version, unpack, pack);

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Message {
    Version(VersionMessage),
    VersionAck,
    GetFilters(FiltersReq),
    Filters(FiltersResp),
    Filter(FilterEvent),
    GetPeers,
    Peers(Vec<Address>),
    GetFee(Vec<Currency>),
    Fee(Vec<FeeResp>),
    PeerIntroduce(Vec<Address>),
    Reject(RejectMessage),
    Ping([u8;8]),
    Pong([u8;8]),
    GetRates(Vec<RateReq>),
    Rates(Vec<RateResp>),
}

impl Message {
    pub fn id(&self) -> u32 {
        match self {
            Message::Version(_) => 0,
            Message::VersionAck => 1,
            Message::GetFilters(_) => 2,
            Message::Filters(_) => 3,
            Message::Filter(_) => 4,
            Message::GetPeers => 5,
            Message::Peers(_) => 6,
            Message::GetFee(_) => 7,
            Message::Fee(_) => 8,
            Message::PeerIntroduce(_) => 9,
            Message::Reject(_) => 10,
            Message::Ping(_) => 11,
            Message::Pong(_) => 12,
            Message::GetRates(_) => 13,
            Message::Rates(_) => 14,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScanBlock {
    currency: Currency,
    version: Version,
    scan_height: u64,
    height: u64,
}
impl_consensus_encoding!(ScanBlock, currency, version, scan_height, height);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VersionMessage {
    version: Version,
    time: u64,
    nonce: [u8; 8],
    scan_blocks: Vec<ScanBlock>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FiltersReq {
    currency: Currency,
    start: u64,
    amount: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Filter {
    block_id: Vec<u8>,
    filter: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FiltersResp {
    currency: Currency,
    filters: Vec<Filter>
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterEvent {
    currency: Currency,
    height: u64,
    block_id: Vec<u8>,
    filter: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeeBtc {
    currency: Currency,
    fast_conserv: u64,
    fast_econom: u64,
    moderate_conserv: u64,
    moderate_econom: u64,
    cheap_conserv: u64,
    cheap_econom: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeeOther {
    currency: Currency,
    fast: u64,
    moderate: u64,
    cheap: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FeeResp {
    FeeBtc(FeeBtc),
    FeeOther(FeeOther),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RejectData {
    HeaderParsing,
    PayloadParsing,
    InternalError,
    ZeroBytesReceived,
    VersionNotSupported,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RejectMessage {
    id: u32,
    message: String,
    data: RejectData,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RateReq {
    currency: Currency,
    fiats: Vec<Fiat>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RateResp {
    currency: Currency,
    rates: Vec<(Fiat, FixedU64<U7>)>
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn version_test_1() {
        let ver = Version { major: 1, minor: 2, patch: 4 };
        assert_eq!(ver.pack(), 0b0000000100_0000000010_0000000001_00);
        assert_eq!(Version::unpack(0b0000000100_0000000010_0000000001_00), ver);
    }

    #[test]
    fn version_test_2() {
        let ver = Version { major: 2, minor: 0, patch: 0 };
        assert_eq!(ver.pack(), 0b0000000000_0000000000_0000000010_00);
        assert_eq!(Version::unpack(0b0000000000_0000000000_0000000010_00), ver);
    }

    #[test]
    fn address_test_v4() {
        let addr = Address::Ipv4(net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), 4142));
        let bytes = vec![0, 0x2E, 0x10, 127, 0, 0, 1];
        assert_eq!(serialize(&addr), bytes);
        assert_eq!(deserialize::<Address>(&bytes).unwrap(), addr);
    }

    #[test]
    fn address_test_v6() {
        let addr = Address::Ipv6(net::SocketAddrV6::new(net::Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334), 4142, 0, 0));
        let bytes = vec![1, 0x2E, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34];
        assert_eq!(serialize(&addr), bytes);
        assert_eq!(deserialize::<Address>(&bytes).unwrap(), addr);
    }
}
