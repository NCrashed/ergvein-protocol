use std::net;
use fixed::{types::extra::U7, FixedU64};

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

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Address {
    AddressIpv4(net::SocketAddrV4),
    AddressIpv6(net::SocketAddrV6),
}

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
pub struct Version {
    major: u16, // used only 10 bits
    minor: u16,
    patch: u16,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScanBlock {
    currency: Currency,
    version: Version,
    scan_height: u64,
    height: u64,
}

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
