use rand::Rng;
use regex::Regex;

use crate::net::{self, GenNet, IpByteTypeHelper, IpInfo, IpParse, NetV4, NetV6};
use colored::Colorize;
use std::{
    cmp::min,
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr},
    ops::{BitAnd, Not},
};

#[derive(Debug)]
pub struct Task<Net: IpInfo> {
    network: GenNet<Net>,
    subnets: u32,
}

pub type TaskV4 = Task<net::V4>;
pub type TaskV6 = Task<net::V6>;

impl<Net: IpInfo> Task<Net> {
    pub fn target_cidr(&self) -> u8 {
        let num = if self.subnets.is_power_of_two() {
            self.subnets
        } else {
            self.subnets.next_power_of_two()
        };

        let n = num.ilog2().try_into().unwrap_or(self.network.cidr() + 2);
        n + self.network.cidr()
    }

    pub fn new_subnets(&self) -> u32 {
        2u32.pow((self.target_cidr() - self.network.cidr()).into())
    }

    pub fn target_subnetmask_u32(&self) -> u32 {
        net::sn_from_cidr_u32(self.target_cidr())
    }

    pub fn target_subnetmask(&self) -> Net::IpType {
        net::sn_from_cidr_gen::<Net>(self.target_cidr())
    }

    pub fn target_networks(&self) -> Vec<GenNet<Net>>
    where
        <<Net as IpInfo>::Bits as Not>::Output: BitAnd<<Net as IpInfo>::Bits>,
    {
        let tcidr = self.target_cidr();
        let sna = self.network.network_address_bits();

        let networks = Net::Bits::pow(2, (tcidr - self.network.cidr()).into());

        let mut nas = vec![];

        for i in Net::Bits::ZERO..networks {
            let na = Net::calc_subnet_address(
                sna,
                self.network.subnetmask_bits(),
                self.target_cidr(),
                i,
            );
            nas.push(GenNet::<Net>::new(na, tcidr))
        }
        nas
    }

    pub fn print_task_cli(&self, idx: Option<u32>) {
        let idx_str = if let Some(idx) = idx {
            format!("{:4}.: ", idx)
        } else {
            "".to_owned()
        };
        println!(
            "{}{}/{} -> {}",
            idx_str.red(),
            format!("{:>15}", self.network.initial_ip()).blue(),
            format!("{:<2}", self.network.cidr()).green(),
            format!("{}", self.subnets).cyan()
        );
    }

    pub fn print_cli(&self)
    where
        <<Net as IpInfo>::Bits as Not>::Output: BitAnd<<Net as IpInfo>::Bits>,
    {
        let mut nets = "".to_owned();
        for network in self.target_networks().iter() {
            let (hfrom, hto) = network.host();
            nets.push_str(&format!(
                "NA: {} BC: {} Host: {} - {}\n",
                format!("{}", network.network_address()).yellow(),
                format!("{}", network.broadcast_address()).purple(),
                format!("{}", hfrom).on_yellow(),
                format!("{}", hto).on_yellow()
            ));
        }

        let (hfrom, hto) = self.network.host();
        println!(
            r#"
{}/{} in {} Subnetze unterteilen
Netzadresse: {}
Subnetzmaske: {}
Broadcastadresse: {}
Hostbereich: {} - {}
Aufgeteilt in {} Netze mit der Subnetzmaske {} und dem CIDR {}

Netzwerke
{}"#,
            format!("{}", self.network.initial_ip()).blue(),
            format!("{}", self.network.cidr()).green(),
            format!("{}", self.subnets).cyan(),
            format!("{}", self.network.network_address()).yellow(),
            format!("{}", self.network.subnetmask()).green(),
            format!("{}", self.network.broadcast_address()).purple(),
            format!("{}", hfrom).on_yellow(),
            format!("{}", hto).on_yellow(),
            format!("{}", self.new_subnets()).cyan(),
            format!("{}", self.target_subnetmask()).green(),
            format!("{}", self.target_cidr()).green(),
            nets
        );
    }
}

pub trait TaskGen<Net: IpInfo> {
    fn rand(min_subnets: u32, max_subnets: u32, min_cidr: u8, max_cidr: u8) -> Self;
    fn parse(text: &str) -> Self;
}

impl TaskGen<net::V4> for Task<net::V4> {
    fn rand(min_subnets: u32, max_subnets: u32, min_cidr: u8, max_cidr: u8) -> Self {
        if min_cidr > 32 || max_cidr > 32 {
            panic!()
        }

        let mut rng = rand::thread_rng();
        let source: u8 = rng.gen_range(min_cidr..=max_cidr);
        let target: u32 = rng
            .gen_range(min_subnets..=min(2u32.pow((30 - source).into()), max_subnets))
            .try_into()
            .unwrap_or(32);
        let ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
        Task {
            network: NetV4::new(ip, source),
            subnets: target,
        }
    }

    fn parse(text: &str) -> Self {
        let re = Regex::new(
            r"^(?P<net>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\s->\s(?P<networks>\d+).?$",
        )
        .unwrap();
        let caps = re.captures(text).unwrap();
        let net = caps.name("net").unwrap();
        let networks = caps.name("networks").unwrap();

        Task {
            network: NetV4::parse(net.as_str()),
            subnets: networks.as_str().parse().unwrap(),
        }
    }
}

impl TaskGen<net::V6> for Task<net::V6> {
    fn rand(min_subnets: u32, max_subnets: u32, min_cidr: u8, max_cidr: u8) -> Self {
        let max_cidr = min(62, max_cidr);
        if min_cidr > 128 || max_cidr > 128 {
            panic!()
        }
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let _ = rng.gen_range(min_cidr..=max_cidr);
        }
        let source: u8 = rng.gen_range(min_cidr..=max_cidr);
        let target: u32 = rng
            .gen_range(min_subnets..=min(2u32.pow((64 - source).into()), max_subnets))
            .try_into()
            .unwrap_or(32);
        let ip = Ipv6Addr::new(
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        );
        Task {
            network: NetV6::new(ip, source),
            subnets: target,
        }
    }

    fn parse(text: &str) -> Self {
        let re = Regex::new(r"^(?P<net>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/\d{1,2})\s->\s(?P<networks>\d+).?$").unwrap();
        let caps = re.captures(text).unwrap();
        let net = caps.name("net").unwrap();
        let networks = caps.name("networks").unwrap();

        Task {
            network: NetV6::parse(net.as_str()),
            subnets: networks.as_str().parse().unwrap(),
        }
    }
}
