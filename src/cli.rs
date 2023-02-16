
#[derive(clap::Parser, Debug)]
pub enum IpMode {
    #[command(subcommand)]
    V4(Command),
    #[command(subcommand)]
    V6(Command),
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Gen {
        #[arg(default_value_t = 10)]
        count: u32,
        #[arg(long="max", default_value_t = 32)]
        max_subnets: u32,
        #[arg(long="min", default_value_t = 2)]
        min_subnets: u32,
        #[arg(long="mic", default_value_t = 16)]
        min_cidr: u8,
        #[arg(long="mac", default_value_t = 28)]
        max_cidr: u8
    },
    Solve {
        input: String,
    },
}
