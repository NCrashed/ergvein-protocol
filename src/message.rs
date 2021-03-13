use std::{net, io, mem};
use std::io::{Write, Cursor};
use fix::aliases::si::Centi;
use flate2::Compression;
use flate2::write::{GzDecoder, GzEncoder};
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
                let ip = net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                let p: u16 = Decodable::consensus_decode(&mut d)?;
                let addr = net::SocketAddrV4::new(ip, p.to_be());
                Ok(Address::Ipv4(addr))
            }
            1 => {
                let b: [u16; 8] = ipv6_to_be(Decodable::consensus_decode(&mut d)?);
                let ip = net::Ipv6Addr::new(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
                let p: u16 = Decodable::consensus_decode(&mut d)?;
                let addr = net::SocketAddrV6::new(ip, p.to_be(), 0, 0);
                Ok(Address::Ipv6(addr))
            }
            2 => {
                let mut b = [0; 56];
                d.read_exact(&mut b)?;
                let p: u16 = Decodable::consensus_decode(&mut d)?;
                Ok(Address::OnionV3(b, p.to_be()))
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
                    + Encodable::consensus_encode(&sock.port().to_be(), &mut s)?;
                Ok(l)
            },
            Address::Ipv6(sock) => {
                let t: u8 = 1;
                let l = Encodable::consensus_encode(&t, &mut s)?
                    + Encodable::consensus_encode(&sock.ip().octets(), &mut s)?
                    + Encodable::consensus_encode(&sock.port().to_be(), &mut s)?;
                Ok(l)
            },
            Address::OnionV3(b, p) => {
                let t: u8 = 2;
                let l = Encodable::consensus_encode(&t, &mut s)?
                    + s.write(b)?
                    + Encodable::consensus_encode(&p.to_be(), &mut s)?;
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
            Message::GetFilters(msg) => len += write_payload(&mut s, msg)?,
            Message::Filters(msg) => len += write_payload(&mut s, msg)?,
            Message::Filter(msg) => len += write_payload(&mut s, msg)?,
            Message::GetPeers => (),
            Message::Peers(msg) => len += write_payload(&mut s, &LengthVecRef(msg))?,
            Message::GetFee(msg) => len += write_payload(&mut s, &LengthVecRef(msg))?,
            Message::Fee(msg) => len += write_payload(&mut s, &LengthVecRef(msg))?,
            Message::PeerIntroduce(_) => (),
            Message::Reject(msg) => len += write_payload(&mut s, msg)?,
            Message::Ping(msg) => len += write_payload(&mut s, msg)?,
            Message::Pong(msg) => len += write_payload(&mut s, msg)?,
            Message::GetRates(msg) => len += write_payload(&mut s, &LengthVecRef(msg))?,
            Message::Rates(msg) => len += write_payload(&mut s, &LengthVecRef(msg))?,
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
            2 => read_payload(&mut d, |buf| {
                Ok(Message::GetFilters(deserialize::<FiltersReq>(&buf)?))
            }),
            3 => read_payload(&mut d, |buf| {
                Ok(Message::Filters(deserialize::<FiltersResp>(&buf)?))
            }),
            4 => read_payload(&mut d, |buf| {
                Ok(Message::Filter(deserialize::<FilterEvent>(&buf)?))
            }),
            5 => Ok(Message::GetPeers),
            6 => read_payload(&mut d, |buf| {
                Ok(Message::Peers(deserialize::<LengthVec<Address>>(&buf)?.0))
            }),
            7 => read_payload(&mut d, |buf| {
                Ok(Message::GetFee(deserialize::<LengthVec<Currency>>(&buf)?.0))
            }),
            8 => read_payload(&mut d, |buf| {
                Ok(Message::Fee(deserialize::<LengthVec<FeeResp>>(&buf)?.0))
            }),
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
            13 => read_payload(&mut d, |buf| {
                Ok(Message::GetRates(deserialize::<LengthVec<RateReq>>(&buf)?.0))
            }),
            14 => read_payload(&mut d, |buf| {
                Ok(Message::Rates(deserialize::<LengthVec<RateResp>>(&buf)?.0))
            }),
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

impl Encodable for FiltersReq {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.currency.consensus_encode(&mut s)?;
        len += VarInt(self.start).consensus_encode(&mut s)?;
        len += VarInt(self.amount as u64).consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for FiltersReq {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<FiltersReq, consensus_encode::Error> {
        Ok(FiltersReq {
            currency: Decodable::consensus_decode(&mut d)?,
            start: VarInt::consensus_decode(&mut d)?.0,
            amount: VarInt::consensus_decode(&mut d)?.0 as u32,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Filter {
    block_id: Vec<u8>,
    filter: Vec<u8>,
}

impl Encodable for Filter {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += s.write(&self.block_id)?;
        len += self.filter.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for Filter {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<Filter, consensus_encode::Error> {
        let bid: [u8; 32] = Decodable::consensus_decode(&mut d)?;
        Ok(Filter {
            block_id: bid.to_vec(),
            filter: Decodable::consensus_decode(&mut d)?,
        })
    }
}


#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FiltersResp {
    currency: Currency,
    filters: Vec<Filter>
}

impl Encodable for FiltersResp {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.currency.consensus_encode(&mut s)?;
        len += VarInt(self.filters.len() as u64).consensus_encode(&mut s)?;

        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        for f in &self.filters {
            e.write_all(&serialize(&f))?;
        }
        let compressed_bytes = e.finish()?;
        s.write_all(&compressed_bytes)?;
        len += compressed_bytes.len();

        Ok(len)
    }
}

impl Decodable for FiltersResp {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<FiltersResp, consensus_encode::Error> {
        let cur = Decodable::consensus_decode(&mut d)?;
        let amount = VarInt::consensus_decode(&mut d)?.0;

        let mut buf = vec![];
        d.read_to_end(&mut buf)?;
        let mut gz = GzDecoder::new(Vec::new());
        gz.write_all(&buf)?;
        let uncompressed = gz.finish()?;

        let mut decoder = Cursor::new(uncompressed);
        let mut fs = vec![];
        for _ in 0 .. amount {
            fs.push(Filter::consensus_decode(&mut decoder)?);
        }

        Ok(FiltersResp {
            currency: cur,
            filters: fs,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterEvent {
    currency: Currency,
    height: u64,
    block_id: Vec<u8>,
    filter: Vec<u8>,
}

impl Encodable for FilterEvent {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.currency.consensus_encode(&mut s)?;
        len += VarInt(self.height).consensus_encode(&mut s)?;
        s.write_all(&self.block_id)?;
        len += self.block_id.len();
        len += self.filter.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for FilterEvent {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<FilterEvent, consensus_encode::Error> {
        let mut buf = [0; 32];
        Ok(FilterEvent {
            currency: Decodable::consensus_decode(&mut d)?,
            height: VarInt::consensus_decode(&mut d)?.0,
            block_id: { d.read_exact(&mut buf)?; buf.to_vec() },
            filter: Decodable::consensus_decode(&mut d)?,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeeBtc {
    fast_conserv: u64,
    fast_econom: u64,
    moderate_conserv: u64,
    moderate_econom: u64,
    cheap_conserv: u64,
    cheap_econom: u64,
}

impl Encodable for FeeBtc {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.fast_conserv).consensus_encode(&mut s)?;
        len += VarInt(self.fast_econom).consensus_encode(&mut s)?;
        len += VarInt(self.moderate_conserv).consensus_encode(&mut s)?;
        len += VarInt(self.moderate_econom).consensus_encode(&mut s)?;
        len += VarInt(self.cheap_conserv).consensus_encode(&mut s)?;
        len += VarInt(self.cheap_econom).consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for FeeBtc {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<FeeBtc, consensus_encode::Error> {
        Ok(FeeBtc {
            fast_conserv: VarInt::consensus_decode(&mut d)?.0,
            fast_econom: VarInt::consensus_decode(&mut d)?.0,
            moderate_conserv: VarInt::consensus_decode(&mut d)?.0,
            moderate_econom: VarInt::consensus_decode(&mut d)?.0,
            cheap_conserv: VarInt::consensus_decode(&mut d)?.0,
            cheap_econom: VarInt::consensus_decode(&mut d)?.0,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeeOther {
    fast: u64,
    moderate: u64,
    cheap: u64,
}

impl Encodable for FeeOther {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.fast).consensus_encode(&mut s)?;
        len += VarInt(self.moderate).consensus_encode(&mut s)?;
        len += VarInt(self.cheap).consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for FeeOther {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<FeeOther, consensus_encode::Error> {
        Ok(FeeOther {
            fast: VarInt::consensus_decode(&mut d)?.0,
            moderate: VarInt::consensus_decode(&mut d)?.0,
            cheap: VarInt::consensus_decode(&mut d)?.0,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FeeResp {
    FeeBtc((Currency, FeeBtc)),
    FeeOther((Currency, FeeOther)),
}

impl Encodable for FeeResp {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        match self {
            FeeResp::FeeBtc((currency, fee)) => {
                assert_eq!(*currency == Currency::Btc || *currency == Currency::TBtc, true, "FeeBtc currency must be Btc or TBtc!");
                len += currency.consensus_encode(&mut s)?;
                len += fee.consensus_encode(&mut s)?
            },
            FeeResp::FeeOther((currency, fee)) => {
                len += currency.consensus_encode(&mut s)?;
                len += fee.consensus_encode(&mut s)?
            }
        }
        Ok(len)
    }
}

impl Decodable for FeeResp {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<FeeResp, consensus_encode::Error> {
        let cur = Currency::consensus_decode(&mut d)?;
        match cur {
            Currency::Btc | Currency::TBtc => Ok(FeeResp::FeeBtc((cur, Decodable::consensus_decode(&mut d)?))),
            _ => Ok(FeeResp::FeeOther((cur, Decodable::consensus_decode(&mut d)?))),
        }
    }
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

impl Encodable for RateReq {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.currency.consensus_encode(&mut s)?;
        len += LengthVecRef(&self.fiats).consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for RateReq {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<RateReq, consensus_encode::Error> {
        Ok(RateReq {
            currency: Decodable::consensus_decode(&mut d)?,
            fiats: LengthVec::consensus_decode(&mut d)?.0,
        })
    }
}

/// Fiat value with 2 decimals after point
pub type Rate = Centi<u64>;

struct RateWord(Rate);

impl Encodable for RateWord {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let w: u64 = self.0.bits;
        let len = w.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for RateWord {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<RateWord, consensus_encode::Error> {
        let w: u64 = Decodable::consensus_decode(&mut d)?;
        Ok(RateWord(Rate::new(w)))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FiatRate {
    fiat: Fiat,
    rate: Rate,
}

impl Encodable for FiatRate {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.fiat.consensus_encode(&mut s)?;
        len += RateWord(self.rate).consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for FiatRate {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<FiatRate, consensus_encode::Error> {
        Ok(FiatRate {
            fiat: Decodable::consensus_decode(&mut d)?,
            rate: RateWord::consensus_decode(&mut d)?.0,
        })
    }
}


#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RateResp {
    currency: Currency,
    rates: Vec<FiatRate>
}

impl Encodable for RateResp {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.currency.consensus_encode(&mut s)?;
        len += LengthVecRef(&self.rates).consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for RateResp {
    #[inline]
    fn consensus_decode<D: io::Read>(
        mut d: D,
    ) -> Result<RateResp, consensus_encode::Error> {
        Ok(RateResp {
            currency: Decodable::consensus_decode(&mut d)?,
            rates: LengthVec::consensus_decode(&mut d)?.0,
        })
    }
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
        let bytes = vec![0, 127, 0, 0, 1, 0x10, 0x2E];
        assert_eq!(serialize(&addr), bytes);
        assert_eq!(deserialize::<Address>(&bytes).unwrap(), addr);
    }

    #[test]
    fn address_test_v6() {
        let addr = Address::Ipv6(net::SocketAddrV6::new(net::Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334), 4142, 0, 0));
        let bytes = vec![1, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, 0x10, 0x2E ];
        assert_eq!(serialize(&addr), bytes);
        assert_eq!(deserialize::<Address>(&bytes).unwrap(), addr);
    }

    #[test]
    fn address_test_onion() {
        let addr = Address::OnionV3(*b"jamie22ezawwi5r3o7lrgsno43jj7vq5en74czuw6wfmjzkhjjryxnid", 9150);
        let bytes = vec![2, 106, 97, 109, 105, 101, 50, 50, 101, 122, 97, 119, 119, 105, 53, 114, 51, 111, 55, 108, 114, 103, 115, 110, 111, 52, 51, 106, 106, 55, 118, 113, 53, 101, 110, 55, 52, 99, 122, 117, 119, 54, 119, 102, 109, 106, 122, 107, 104, 106, 106, 114, 121, 120, 110, 105, 100, 35, 190];
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

    #[test]
    fn filters_req_test() {
        let msg = Message::GetFilters(FiltersReq {
            currency: Currency::Btc,
            start: 445123,
            amount: 2000,
        });
        let bytes = Vec::from_hex("020900fec3ca0600fdd007").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }

    #[test]
    fn filters_resp_test() {
        let msg = Message::Filters(FiltersResp {
            currency: Currency::Btc,
            filters: vec![
                Filter {
                    block_id: b"12345678123456781234567812345678".to_vec(),
                    filter: b"abcd".to_vec(),
                },
                Filter {
                    block_id: b"22345678123456781234567812345678".to_vec(),
                    filter: b"ffff".to_vec(),
                },
            ],
        });
        let bytes = Vec::from_hex("032b00021f8b080000000000000333343236313533b730c441b3242625a71811529406040096e289844a000000").unwrap();
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
        assert_eq!(deserialize::<Message>(&serialize(&msg)).unwrap(), msg);
    }

    #[test]
    fn filter_event_test() {
        let msg = Message::Filter(FilterEvent {
            currency: Currency::Btc,
            height: 8083,
            block_id: b"12345678123456781234567812345678".to_vec(),
            filter: b"abcd".to_vec(),
        });
        let bytes = Vec::from_hex("042900fd931f31323334353637383132333435363738313233343536373831323334353637380461626364").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }

    #[test]
    fn fee_req_test() {
        let msg = Message::GetFee(vec![Currency::Btc, Currency::Dash]);
        let bytes = Vec::from_hex("070302000c").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }

    #[test]
    fn fee_resp_test() {
        let msg = Message::Fee(vec![
                FeeResp::FeeBtc((Currency::Btc, FeeBtc {
                    fast_conserv: 4,
                    fast_econom: 8,
                    moderate_conserv: 15,
                    moderate_econom: 16,
                    cheap_conserv: 23,
                    cheap_econom: 42,
                })),
                FeeResp::FeeOther((Currency::Dash, FeeOther {
                    fast: 4,
                    moderate: 8,
                    cheap: 15,
                }))
            ]);
        let bytes = Vec::from_hex("080c020004080f10172a0c04080f").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }

    #[test]
    fn peer_req_test() {
        let msg = Message::GetPeers;
        let bytes = Vec::from_hex("05").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }

    #[test]
    fn peer_resp_test() {
        let msg = Message::Peers(vec![
              Address::Ipv4(net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), 8333))
            , Address::Ipv6(net::SocketAddrV6::new(net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 8333, 0, 0))
            , Address::OnionV3(*b"jamie22ezawwi5r3o7lrgsno43jj7vq5en74czuw6wfmjzkhjjryxnid", 9150)
            ]);
        let bytes = Vec::from_hex("065603007f000001208d0100000000000000000000000000000001208d026a616d69653232657a617777693572336f376c7267736e6f34336a6a37767135656e3734637a75773677666d6a7a6b686a6a7279786e696423be").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }

    #[test]
    fn rates_req_test() {
        let msg = Message::GetRates(vec![
                RateReq {
                    currency: Currency::Btc,
                    fiats: vec![Fiat::Usd, Fiat::Rub],
                },
                RateReq {
                    currency: Currency::Dash,
                    fiats: vec![Fiat::Eur, Fiat::Rub],
                },
            ]);
        let bytes = Vec::from_hex("0d0902000200020c020102").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }

    #[test]
    fn rates_resp_test() {
        let msg = Message::Rates(vec![
                RateResp {
                    currency: Currency::Btc,
                    rates: vec![
                      FiatRate { fiat: Fiat::Usd, rate: Rate::new(65003_23) },
                      FiatRate { fiat: Fiat::Rub, rate: Rate::new(350000_42) },
                    ],
                },
                RateResp {
                    currency: Currency::Dash,
                    rates: vec![
                      FiatRate { fiat: Fiat::Eur, rate: Rate::new(0_12) },
                      FiatRate { fiat: Fiat::Rub, rate: Rate::new(0_01) },
                    ],
                },
            ]);
        let bytes = Vec::from_hex("0e2902000200e32f63000000000002ea0e1602000000000c02010c00000000000000020100000000000000").unwrap();
        assert_eq!(serialize(&msg), bytes);
        assert_eq!(deserialize::<Message>(&bytes).unwrap(), msg);
    }
}
