
#[derive(clap::Parser, Debug)]
pub enum IpMode {
    #[command(subcommand)]
    V4(Command),
    #[command(subcommand)]
    V6(Command)
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Gen {
        #[arg(short, long)]
        tasks: String,
        #[arg(short, long)]
        solutions: String,
    },
    Solve {
        input: String
    }
}
