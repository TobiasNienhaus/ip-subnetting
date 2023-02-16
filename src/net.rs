use regex::Regex;
use std::{net::{Ipv4Addr, Ipv6Addr}, marker::PhantomData, mem::size_of, ops::{BitAnd, Not, BitOr}};

pub trait IpByteTypeHelper {
    const MAX: Self;
    const BITS: u8;
    const ONE: Self;
}

impl IpByteTypeHelper for u32 {
    const MAX: u32 = u32::MAX;
    const BITS: u8 = u32::BITS as u8;
    const ONE: u32 = 1u32;
}

impl IpByteTypeHelper for u128 {
    const MAX: u128 = u128::MAX;
    const BITS: u8 = u128::BITS as u8;
    const ONE: u128 = 1u128;
}

pub trait IpByteType: IpByteTypeHelper + num::Unsigned + std::ops::Shl<u8, Output = Self> + BitAnd + Not + BitOr + Clone {}
impl<T> IpByteType for T where T: IpByteTypeHelper + num::Unsigned + std::ops::Shl<u8, Output = Self> + BitAnd + Not + BitOr + Clone {}

pub trait IpTrait<Bits: IpByteType> {
    fn from_proxy(bits: Bits) -> Self;
    fn bits(&self) -> Bits;
}

impl<> IpTrait<u32> for Ipv4Addr {
    fn from_proxy(bits: u32) -> Self {
        Ipv4Addr::from(bits)
    }

    fn bits(&self) -> u32 {
        self.to_owned().into()
    }
}

impl<> IpTrait<u128> for Ipv6Addr {
    fn from_proxy(bits: u128) -> Self {
        Ipv6Addr::from(bits)
    }

    fn bits(&self) -> u128 {
        self.to_owned().into()
    }
}

pub trait IpInfo {
    type Bits: IpByteType 
    + From<<Self::Bits as BitAnd>::Output> 
    + From<<Self::Bits as BitOr>::Output>
    + From<<Self::Bits as Not>::Output>;
    type IpType: IpTrait<Self::Bits> + Copy + Clone;
}


#[derive(Debug)]
pub struct V4 {}
impl IpInfo for V4 {
    type IpType = Ipv4Addr;
    type Bits = u32;
}


#[derive(Debug)]
pub struct V6 {}
impl IpInfo for V6 {
    type IpType = Ipv6Addr;
    type Bits = u128;
}

pub enum IpType {
    V4, V6
}

pub fn sn_from_cidr_gen_bits<Ip: IpInfo>(cidr: u8) -> Ip::Bits {
    Ip::Bits::MAX << (Ip::Bits::BITS - cidr)
}

pub fn sn_from_cidr_gen<Ip: IpInfo>(cidr: u8) -> Ip::IpType {
    Ip::IpType::from_proxy(sn_from_cidr_gen_bits::<Ip>(cidr))
}

pub fn na_from_ip_and_cidr_gen<Ip: IpInfo>(ip: &Ip::IpType, cidr: u8) -> Ip::IpType {
    let source: Ip::Bits = ip.bits();
    Ip::IpType::from_proxy((source & sn_from_cidr_gen_bits::<Ip>(cidr)).into())
}

pub fn bc_from_ip_and_cidr_gen<Ip: IpInfo>(ip: &Ip::IpType, cidr: u8) -> Ip::IpType {
    let mask = !(sn_from_cidr_gen_bits::<Ip>(cidr));
    let source = ip.bits();
    Ip::IpType::from_proxy((source | mask.into()).into())
}

pub fn sn_from_cidr_u32(cidr: u8) -> u32 {
    u32::MAX << (32 - cidr)
}

pub fn sn_from_cidr(cidr: u8) -> Ipv4Addr {
    Ipv4Addr::from(sn_from_cidr_u32(cidr))
}

pub fn na_from_ip_and_cidr(ip: Ipv4Addr, cidr: u8) -> Ipv4Addr {
    let source: u32 = ip.into();
    Ipv4Addr::from(source & sn_from_cidr_u32(cidr))
}

pub fn bc_from_ip_and_cidr(ip: Ipv4Addr, cidr: u8) -> Ipv4Addr {
    let mask = !(u32::MAX << (32 - cidr));
    let source: u32 = ip.into();
    Ipv4Addr::from(source | mask)
}

#[derive(Debug)]
pub struct GenNet<Ip: IpInfo> {
    initial_ip: Ip::IpType,
    na: Ip::IpType,
    bc: Ip::IpType,
    host_from: Ip::IpType,
    host_until: Ip::IpType,
    cidr: u8,
}

pub trait IpParse {
    fn parse(text: &str) -> Self;
}

pub type NetV4 = GenNet<V4>;
pub type NetV6 = GenNet<V6>;

impl<Ip: IpInfo> GenNet<Ip> {
    pub fn new(ip: Ip::IpType, cidr: u8) -> Self {
        
        if size_of::<Ip::Bits>() * 8 < cidr as usize {
            panic!("CIDR to big");
        }

        let na = na_from_ip_and_cidr_gen::<Ip>(&ip, cidr);
        let bc = bc_from_ip_and_cidr_gen::<Ip>(&na, cidr);
        let na_bits = na.bits().clone();
        let bc_bits = bc.bits().clone();
        let from = na_bits + Ip::Bits::ONE;
        let until = bc_bits - Ip::Bits::ONE;
        
        GenNet {
            initial_ip: ip,
            na,
            bc,
            host_from: Ip::IpType::from_proxy(from),
            host_until: Ip::IpType::from_proxy(until),
            cidr
        }
    }

    pub fn network_address(&self) -> Ip::IpType {
        self.na
    }

    pub fn network_address_u32(&self) -> Ip::Bits {
        self.na.bits()
    }

    pub fn broadcast_address(&self) -> Ip::IpType {
        self.bc
    }

    pub fn broadcast_address_u32(&self) -> Ip::Bits {
        self.bc.bits()
    }

    pub fn subnetmask(&self) -> Ip::IpType {
       sn_from_cidr_gen::<Ip>(self.cidr)
    }

    pub fn subnetmask_u32(&self) -> Ip::Bits {
        sn_from_cidr_gen_bits::<Ip>(self.cidr)
    }

    pub fn host(&self) -> (Ip::IpType, Ip::IpType) {
        (self.host_from, self.host_until)
    }

    pub fn host_u32(&self) -> (Ip::Bits, Ip::Bits) {
        (self.host_from.bits(), self.host_until.bits())
    }

    pub fn initial_ip(&self) -> Ip::IpType {
        self.initial_ip
    }

    pub fn cidr(&self) -> u8 {
        self.cidr
    }
}

impl IpParse for NetV4 {
    fn parse(text: &str) -> Self {
        let re = Regex::new(r"^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?P<cidr>\d{1,2}).?$").unwrap();
        let caps = re.captures(text).unwrap();
        let ip = caps.name("ip").unwrap();
        let cidr = caps.name("cidr").unwrap();
        
        NetV4::new(ip.as_str().parse().unwrap(), cidr.as_str().parse().unwrap())
    }
}

impl IpParse for NetV6 {
    fn parse(text: &str) -> Self {
        todo!("Regex fehlt noch");
        let re = Regex::new(r"^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?P<cidr>\d{1,2}).?$").unwrap();
        let caps = re.captures(text).unwrap();
        let ip = caps.name("ip").unwrap();
        let cidr = caps.name("cidr").unwrap();
        
        NetV6::new(ip.as_str().parse().unwrap(), cidr.as_str().parse().unwrap())
    }
}
