use std::net;

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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VersionMessage {

}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FiltersReq {

}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FiltersResp {

}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterEvent {

}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeeResp {

}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RejectMessage {

}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RateReq {

}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RateResp {

}
