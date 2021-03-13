use std::{net, io, mem};
use fixed::types::extra::U7;
use fixed::FixedU64;
pub use consensus_encode::{Error, Decodable, Encodable, deserialize, deserialize_partial, serialize, serialize_hex, MAX_VEC_SIZE, VarInt};

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

struct LengthVec<T>(Vec<T>);

impl<T: Decodable> Decodable for LengthVec<T> {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = VarInt::consensus_decode(&mut d)?.0;
        let byte_size = (len as usize)
                            .checked_mul(mem::size_of::<T>())
                            .ok_or(Error::ParseFailed("Invalid length"))?;
        if byte_size > MAX_VEC_SIZE {
            return Err(Error::OversizedVectorAllocation { requested: byte_size, max: MAX_VEC_SIZE })
        }
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(&mut d)?);
        }
        Ok(LengthVec(ret))
    }
}

struct LengthVecRef<'a, T>(&'a Vec<T>);

impl<'a, T: Encodable> Encodable for LengthVecRef<'a, T> {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.0.len() as u64).consensus_encode(&mut s)?;
        for c in self.0.iter() {
            len += c.consensus_encode(&mut s)?;
        }
        Ok(len)
    }
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
    Unknown(u32),
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
            Currency::Unknown(i) => *i,
        }
    }

    pub fn from_index(i: u32) -> Self {
        match i {
            0 => Currency::Btc,
            1 => Currency::TBtc,
            2 => Currency::Ergo,
            3 => Currency::TErgo,
            4 => Currency::UsdtOmni,
            5 => Currency::TUsdtOmni,
            6 => Currency::Ltc,
            7 => Currency::TLtc,
            8 => Currency::Zec,
            9 => Currency::TZec,
            10 => Currency::Cpr,
            11 => Currency::TCpr,
            12 => Currency::Dash,
            13 => Currency::TDash,
            i => Currency::Unknown(i),
        }
    }

    fn pack(&self) -> VarInt {
        VarInt(self.to_index() as u64)
    }

    fn unpack(i: VarInt) -> Self {
        Currency::from_index(i.0 as u32)
    }
}
impl_pure_encodable!(Currency, unpack, pack);


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fiat {
    Usd,
    Eur,
    Rub,
    Unknown(u32),
}

impl Fiat {
    pub fn to_index(&self) -> u32 {
        match self {
            Fiat::Usd => 0,
            Fiat::Eur => 1,
            Fiat::Rub => 2,
            Fiat::Unknown(i) => *i,
        }
    }

    pub fn from_index(i: u32) -> Self {
        match i {
            0 => Fiat::Usd,
            1 => Fiat::Eur,
            2 => Fiat::Rub,
            i => Fiat::Unknown(i),
        }
    }

    fn pack(&self) -> VarInt {
        VarInt(self.to_index() as u64)
    }

    fn unpack(i: VarInt) -> Self {
        Fiat::from_index(i.0 as u32)
    }
}
impl_pure_encodable!(Fiat, unpack, pack);

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Address {
    Ipv4(net::SocketAddrV4),
    Ipv6(net::SocketAddrV6),
    OnionV3([u8; 56], u16),
}

fn ipv6_to_be(addr: [u16; 8]) -> [u16; 8] {
    [addr[0].to_be(), addr[1].to_be(), addr[2].to_be(), addr[3].to_be(),
     addr[4].to_be(), addr[5].to_be(), addr[6].to_be(), addr[7].to_be()]
}

impl Decodable for Address {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let t: u8 = Decodable::consensus_decode(&mut d)?;
        match t {
            0 => {
                let b: [u8; 4] = Decodable::consensus_decode(&mut d)?;
                let p: u16 = Decodable::consensus_decode(&mut d)?;
                let ip = net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                let addr = net::SocketAddrV4::new(ip, p);
                Ok(Address::Ipv4(addr))
            }
            1 => {
                let b: [u16; 8] = ipv6_to_be(Decodable::consensus_decode(&mut d)?);
                let p: u16 = Decodable::consensus_decode(&mut d)?;
                let ip = net::Ipv6Addr::new(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
                let addr = net::SocketAddrV6::new(ip, p, 0, 0);
                Ok(Address::Ipv6(addr))
            }
            2 => {
                let mut b = [0; 56];
                d.read_exact(&mut b)?;
                let p: u16 = Decodable::consensus_decode(&mut d)?;
                Ok(Address::OnionV3(b, p))
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
                    + Encodable::consensus_encode(&sock.ip().octets(), &mut s)?
                    + Encodable::consensus_encode(&sock.port(), &mut s)?;
                Ok(l)
            },
            Address::Ipv6(sock) => {
                let t: u8 = 1;
                let l = Encodable::consensus_encode(&t, &mut s)?
                    + Encodable::consensus_encode(&sock.ip().octets(), &mut s)?
                    + Encodable::consensus_encode(&sock.port(), &mut s)?;
                Ok(l)
            },
            Address::OnionV3(b, p) => {
                let t: u8 = 2;
                let l = Encodable::consensus_encode(&t, &mut s)?
                    + s.write(b)?
                    + Encodable::consensus_encode(p, &mut s)?;
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
    /// Current implemented version
    pub fn current() -> Self {
        Version {
            major: 2,
            minor: 0,
            patch: 0,
        }
    }

    /// Check whether versions compatible
    pub fn compatible(&self, v: &Self) -> bool {
        self.major == v.major
    }

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

    fn pack_be(&self) -> u32 { self.pack().to_be() }
    fn unpack_be(w: u32) -> Self { Version::unpack(w.to_be()) }
}
impl_pure_encodable!(Version, unpack_be, pack_be);

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

/// Maximum size of message in bytes
pub const MAX_MESSAGE_SIZE: usize = 10*1024*1024;

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

impl Encodable for Message {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {

        fn write_payload<S, T>(mut s: &mut S, v: &T) -> Result<usize, io::Error>
            where
            S: io::Write,
            T: Encodable + ?Sized,
        {
            let payload = serialize(v);
            let mut len = 0;
            len += VarInt(payload.len() as u64).consensus_encode(&mut s)?;
            len += s.write(&payload)?;
            Ok(len)
        }

        let mut len = 0;
        len += VarInt(self.id() as u64).consensus_encode(&mut s)?;
        match self {
            Message::Version(msg) => len += write_payload(&mut s, msg)?,
            Message::VersionAck => (),
            Message::GetFilters(_) => (),
            Message::Filters(_) => (),
            Message::Filter(_) => (),
            Message::GetPeers => (),
            Message::Peers(_) => (),
            Message::GetFee(_) => (),
            Message::Fee(_) => (),
            Message::PeerIntroduce(_) => (),
            Message::Reject(msg) => len += write_payload(&mut s, msg)?,
            Message::Ping(msg) => len += write_payload(&mut s, msg)?,
            Message::Pong(msg) => len += write_payload(&mut s, msg)?,
            Message::GetRates(_) => (),
            Message::Rates(_) => (),
        }
        Ok(len)
    }
}

impl Decodable for Message {
    #[inline]
    fn consensus_decode<D: ::std::io::Read>(
        mut d: D,
    ) -> Result<Message, consensus_encode::Error> {

        fn read_payload<F, D>(mut d: &mut D, mut f: F) -> Result<Message, consensus_encode::Error>
            where
            F: FnMut(&mut [u8]) -> Result<Message, consensus_encode::Error>,
            D: io::Read,
        {
            let len = VarInt::consensus_decode(&mut d)?.0 as u32;
            if len as usize > MAX_MESSAGE_SIZE {
                Err(Error::ParseFailed("Message size is too large"))
            } else {
                let mut buf = vec![0; len as usize];
                d.read_exact(&mut buf)?;
                f(&mut buf)
            }
        }

        let id = VarInt::consensus_decode(&mut d)?.0 as u32;
        match id {
            0 => read_payload(&mut d, |buf| {
                Ok(Message::Version(deserialize::<VersionMessage>(&buf)?))
            }),
            1 => Ok(Message::VersionAck),
            // 2 => ,
            // 3 => ,
            // 4 => ,
            5 => Ok(Message::GetPeers),
            // 6 => ,
            // 7 => ,
            // 8 => ,
            // 9 => ,
            10 => read_payload(&mut d, |buf| {
                Ok(Message::Reject(deserialize::<RejectMessage>(&buf)?))
            }),
            11 => read_payload(&mut d, |buf| {
                let mut nonce: [u8; 8] = Default::default();
                nonce.copy_from_slice(&buf[0 .. 8]);
                Ok(Message::Ping(nonce))
            }),
            12 => read_payload(&mut d, |buf| {
                let mut nonce: [u8; 8] = Default::default();
                nonce.copy_from_slice(&buf[0 .. 8]);
                Ok(Message::Pong(nonce))
            }),
            // 13 => ,
            // 14 => ,
            _ => Err(Error::ParseFailed("Unknown message type")),
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

impl Encodable for ScanBlock {
    #[inline]
    fn consensus_encode<S: ::std::io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, ::std::io::Error> {
        let mut len = 0;
        len += self.currency.consensus_encode(&mut s)?;
        len += self.version.consensus_encode(&mut s)?;
        len += VarInt(self.scan_height).consensus_encode(&mut s)?;
        len += VarInt(self.height).consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for ScanBlock {
    #[inline]
    fn consensus_decode<D: ::std::io::Read>(
        mut d: D,
    ) -> Result<ScanBlock, consensus_encode::Error> {
        Ok(ScanBlock {
            currency: Decodable::consensus_decode(&mut d)?,
            version: Decodable::consensus_decode(&mut d)?,
            scan_height: VarInt::consensus_decode(&mut d)?.0,
            height: VarInt::consensus_decode(&mut d)?.0,
        })
    }
}


#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VersionMessage {
    version: Version,
    time: u64,
    nonce: [u8; 8],
    scan_blocks: Vec<ScanBlock>,
}

impl Encodable for VersionMessage {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.time.consensus_encode(&mut s)?;
        len += self.nonce.consensus_encode(&mut s)?;
        len += LengthVecRef(&self.scan_blocks).consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for VersionMessage {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<VersionMessage, consensus_encode::Error> {
        Ok(VersionMessage {
            version: Decodable::consensus_decode(&mut d)?,
            time: Decodable::consensus_decode(&mut d)?,
            nonce: Decodable::consensus_decode(&mut d)?,
            scan_blocks: LengthVec::consensus_decode(&mut d)?.0,
        })
    }
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
    Unknown(u32),
}

impl RejectData {
    pub fn to_code(&self) -> u32 {
        match self {
            RejectData::HeaderParsing => 0,
            RejectData::PayloadParsing => 1,
            RejectData::InternalError => 2,
            RejectData::ZeroBytesReceived => 3,
            RejectData::VersionNotSupported => 4,
            RejectData::Unknown(i) => *i,
        }
    }

    pub fn from_code(i: u32) -> Self {
        match i {
            0 => RejectData::HeaderParsing,
            1 => RejectData::PayloadParsing,
            2 => RejectData::InternalError,
            3 => RejectData::ZeroBytesReceived,
            4 => RejectData::VersionNotSupported,
            i => RejectData::Unknown(i),
        }
    }

    fn pack(&self) -> VarInt {
        VarInt(self.to_code() as u64)
    }

    fn unpack(i: VarInt) -> Self {
        RejectData::from_code(i.0 as u32)
    }
}
impl_pure_encodable!(RejectData, unpack, pack);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RejectMessage {
    id: u32,
    data: RejectData,
    message: String,
}

impl Encodable for RejectMessage {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.id as u64).consensus_encode(&mut s)?;
        len += self.data.consensus_encode(&mut s)?;
        len += self.message.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for RejectMessage {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<RejectMessage, consensus_encode::Error> {
        Ok(RejectMessage {
            id: VarInt::consensus_decode(&mut d)?.0 as u32,
            data: Decodable::consensus_decode(&mut d)?,
            message: Decodable::consensus_decode(&mut d)?,
        })
    }
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
    use consensus_encode::util::hex::FromHex;

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
        let bytes = vec![0, 127, 0, 0, 1, 0x2E, 0x10];
        assert_eq!(serialize(&addr), bytes);
        assert_eq!(deserialize::<Address>(&bytes).unwrap(), addr);
    }

    #[test]
    fn address_test_v6() {
        let addr = Address::Ipv6(net::SocketAddrV6::new(net::Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334), 4142, 0, 0));
        let bytes = vec![1, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, 0x2E, 0x10 ];
        assert_eq!(serialize(&addr), bytes);
        assert_eq!(deserialize::<Address>(&bytes).unwrap(), addr);
    }

    #[test]
    fn version_msg_test() {
        let msg = Message::Version(VersionMessage {
            version: Version { major: 1, minor: 2, patch: 4},
            time: 1615562102,
            nonce: [0, 1, 2, 3, 4, 5, 6, 7],
            scan_blocks: vec![
                ScanBlock {
                    currency: Currency::Btc,
                    version: Version { major: 1, minor: 2, patch: 4},
                    scan_height: 674299,
                    height: 300000,
                },
                ScanBlock {
                    currency: Currency::Ergo,
                    version: Version { major: 4, minor: 1, patch: 0},
                    scan_height: 374299,
                    height: 200000,
                }
            ],
        });
        let bytes = Vec::from_hex("00330100200476854b60000000000001020304050607020001002004fefb490a00fee09304000200001010fe1bb60500fe400d0300").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }

    #[test]
    fn verack_msg_test() {
        let msg = Message::VersionAck;
        let bytes = Vec::from_hex("01").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }

    #[test]
    fn ping_msg_test() {
        let msg = Message::Ping([0xCF, 0x78, 0x06, 0, 0, 0, 0, 0]);
        let bytes = Vec::from_hex("0b08cf78060000000000").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }

    #[test]
    fn pong_msg_test() {
        let msg = Message::Pong([0xCF, 0x78, 0x06, 0, 0, 0, 0, 0]);
        let bytes = Vec::from_hex("0c08cf78060000000000").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }

    #[test]
    fn reject_msg_test() {
        let msg = Message::Reject(RejectMessage {
            id: 2,
            data: RejectData::InternalError,
            message: "Something went wrong".to_string(),
        });
        let bytes = Vec::from_hex("0a17020214536f6d657468696e672077656e742077726f6e67").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }
}
