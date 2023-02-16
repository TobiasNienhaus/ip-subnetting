#![feature(step_trait)]

mod cli;
mod net;
mod task;

use clap::Parser;
use task::{TaskGen, TaskV4};

use crate::task::TaskV6;

fn handle_v4(cmd: cli::Command) {
    match cmd {
        cli::Command::Gen { count, max_subnets, min_subnets, min_cidr, max_cidr } => {
            for i in 1..=count {
                TaskV4::rand(min_subnets, max_subnets, min_cidr, max_cidr).print_task_cli(Some(i));
            }
        }
        cli::Command::Solve { input } => {
            TaskV4::parse(&input).print_cli();
        }
    }
}

fn handle_v6(cmd: cli::Command) {
    match cmd {
        cli::Command::Gen { count, max_subnets, min_subnets, min_cidr, max_cidr } => {
            for i in 1..=count {
                TaskV6::rand(min_subnets, max_subnets, min_cidr, max_cidr).print_task_cli(Some(i));
            }
        }
        cli::Command::Solve { input } => {
            TaskV6::parse(&input).print_cli();
        }
    }
}

fn main() {
    let args = cli::IpMode::parse();

    match args {
        cli::IpMode::V4(cmd) => handle_v4(cmd),
        cli::IpMode::V6(cmd) => handle_v6(cmd),
    }
}
