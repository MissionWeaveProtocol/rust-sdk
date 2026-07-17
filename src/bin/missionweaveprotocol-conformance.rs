//! `MissionWeaveProtocol` schema-and-vector conformance CLI.

use std::process::ExitCode;

use clap::Parser;
use missionweaveprotocol::ConformanceRunner;

#[derive(Debug, Parser)]
#[command(
    name = "missionweaveprotocol-conformance",
    version,
    about = "Run embedded MissionWeaveProtocol schema conformance vectors"
)]
struct Arguments {
    /// Print passing vector names as well as failures.
    #[arg(long)]
    verbose: bool,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    let report = match ConformanceRunner::new().and_then(|runner| runner.run()) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("conformance runner failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    for result in &report.results {
        if arguments.verbose || !result.passed() {
            let state = if result.passed() { "PASS" } else { "FAIL" };
            println!("{state}\t{}", result.name);
            if let Some(error) = &result.error
                && !result.passed()
            {
                println!("  {error}");
            }
        }
    }
    println!("{}", report.summary());

    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
