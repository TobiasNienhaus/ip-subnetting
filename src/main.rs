mod net;
mod cli;

use std::{net::{Ipv4Addr, Ipv6Addr}, fmt::format, cmp::min, fs::File};
use clap::Parser;
use rand::Rng;
use regex::Regex;
use std::io::Write;
use net::{NetV6, IpParse};

#[derive(Debug)]
struct Aufgabe {
    network: NetV6,
    subnets: u8
}

impl Aufgabe {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let source: u8 = rng.gen_range(16..=28);
        let target: u8 = rng.gen_range(2..=min(2u32.pow((30-source).into()),32)).try_into().unwrap_or(32);
        let ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
        let ip = Ipv6Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen());
        Aufgabe {
            network: NetV6::new(ip, source),
            subnets: target
        }
    }

    pub fn parse(text: &str) -> Self {
        let re = Regex::new(r"^(?P<net>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\s->\s(?P<networks>\d{1,2}).?$").unwrap();
        let caps = re.captures(text).unwrap();
        let net = caps.name("net").unwrap();
        let networks = caps.name("networks").unwrap();

        Aufgabe {
            network: NetV6::parse(net.as_str()),
            subnets: networks.as_str().parse().unwrap()
        }
    }

    pub fn target_cidr(&self) -> u8 {
        let num = if self.subnets.is_power_of_two() {
            self.subnets
        } else {
            self.subnets.next_power_of_two()
        };

        let n = num.ilog2().try_into().unwrap_or(self.network.cidr() + 2);
        n + self.network.cidr()
    }

    pub fn new_subnets(&self) -> u8 {
        2u8.pow((self.target_cidr() - self.network.cidr()).into())
    }

    pub fn target_subnetmask_u32(&self) -> u32 {
        net::sn_from_cidr_u32(self.target_cidr())
    }

    pub fn target_subnetmask(&self) -> Ipv4Addr {
        net::sn_from_cidr(self.target_cidr())
    }

    pub fn target_networks(&self) -> Vec<NetV6> {
        let tcidr = self.target_cidr();
        let sna = self.network.network_address_u32();

        let networks = 2u128.pow((tcidr - self.network.cidr()).into());

        let mask = (!self.network.subnetmask_u32()) & net::sn_from_cidr_gen_bits::<net::V6>(self.target_cidr());

        let mut nas = vec![];

        for i in 0u128..networks {
            let num = (i << (128 - tcidr)) & mask;
            let na = Ipv6Addr::from(num | sna);
            nas.push(NetV6::new(na, tcidr))
        }
        nas
    }
}

fn task_to_solution(index: usize, task: &Aufgabe) -> String {
    let new_nets = task.target_networks();
    let mut table = "".to_owned();

    for (idx, network) in new_nets.iter().enumerate() {
        let (host_from, host_until) = network.host();
        table.push_str(&format!("|{}|{}|{}|{} - {}|\n", (idx+1), network.network_address(), network.broadcast_address(), host_from, host_until));
    }

    let (host_from, host_until) = task.network.host();

    format!(r#"
## {}.: {}/{} in {} unterteilen

Netzadresse: {}

Subnetzmaske: {}

Broadcastadresse: {}

Hostbereich: {} - {}

Aufgeteilt in {} Netze mit der Subnetzmaske {} und dem CIDR {}

|Nr.|Netzadresse|Broadcastadresse|Hostanteil|
|---|---|---|---|
{}
<div style="page-break-after: always;"></div>"#, index + 1,
        task.network.initial_ip(),
        task.network.cidr(),
        task.subnets,
        task.network.network_address(),
        task.network.subnetmask(),
        task.network.broadcast_address(),
        host_from,
        host_until,
        task.new_subnets(),
        task.target_subnetmask(),
        task.target_cidr(),
        table
    )
}

fn handle_v4(cmd: cli::Command) {
    match cmd {
        cli::Command::Gen { tasks, solutions } => {
            println!("tasks: {}", tasks);
            println!("solutions: {}", solutions);
        },
        cli::Command::Solve { input } => {
            // let task = Aufgabe::parse(&input);
            let task = Aufgabe::new();
            println!("{:?}", task);
            println!("{:#?}", task.target_networks());
        }
    }
}

fn handle_v6(cmd: cli::Command) {
    println!("{:?}", cmd)
}

fn main() {
    let args = cli::IpMode::parse();

    match args {
        cli::IpMode::V4(cmd) => handle_v4(cmd),
        cli::IpMode::V6(cmd) => handle_v6(cmd)
    }

    // let mut tasks = vec![];
    // for i in 0..100 {
    //     tasks.push(Aufgabe::new());
    // }

    // let mut task_lines = vec![];
    // let mut solutions = vec![];

    // for (idx, task) in tasks.iter().enumerate() {
    //     task_lines.push(format!("{}. {}/{} in {} Subnetze unterteilen", idx, task.network.initial_ip(), task.network.cidr(), task.subnets));
    //     solutions.push(task_to_solution(idx, task));
    // }
    // let task = format!("# Aufgaben:\n{}", task_lines.join("\n"));
    // let solution = format!("# Lösungen:\n{}", solutions.join("\n"));

    // let mut task_out = File::create("tasks.md").unwrap();
    // write!(task_out, "{}", task).unwrap();

    // let mut solution_out = File::create("solutions.md").unwrap();
    // write!(solution_out, "{}", solution).unwrap();
}
