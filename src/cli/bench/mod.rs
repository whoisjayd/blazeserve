//! `blaze benchmark`: the single-download measurement, the repeatable harness and `compare`.

mod compare;
mod environment;
mod fixture;
mod harness;
mod runner;
mod sampler;
mod schema;
mod single;
mod stats;
#[cfg(test)]
mod test_support;
mod validate;

use clap::{Args, Subcommand};
use fixture::DEFAULT_SEED;
use sampler::WorkloadSel;
use std::path::PathBuf;

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct BenchArgs {
    #[command(subcommand)]
    pub command: Option<BenchCommand>,
    /// Existing BlazeServe URL to benchmark instead of a temporary local server
    #[arg(long)]
    pub url: Option<String>,
    /// Size of test download in MB
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..=1000))]
    pub size_mb: u64,
    /// Display machine-readable JSON
    #[arg(long = "json")]
    pub json: bool,
    /// Recorded samples per workload. Any of --runs, --warmup, --workload or --output selects
    /// the repeatable harness
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub runs: Option<u32>,
    /// Discarded warm-up samples before the recorded ones [default: 1]
    #[arg(long, value_parser = clap::value_parser!(u32).range(0..=100))]
    pub warmup: Option<u32>,
    /// Workload to measure [default: full]
    #[arg(long, value_enum)]
    pub workload: Option<WorkloadSel>,
    /// Write the versioned JSON artifact to this file
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Seed for the deterministic fixture content
    #[arg(long, default_value_t = DEFAULT_SEED)]
    pub seed: u64,
}

#[derive(Subcommand, Debug)]
pub enum BenchCommand {
    /// Compare the medians of two benchmark artifacts
    Compare(CompareArgs),
}

#[derive(Args, Debug)]
pub struct CompareArgs {
    /// Baseline artifact
    pub a: PathBuf,
    /// Candidate artifact
    pub b: PathBuf,
    /// Display machine-readable JSON
    #[arg(long = "json")]
    pub json: bool,
}

pub fn run(args: BenchArgs) -> Result<u8, String> {
    if let Some(BenchCommand::Compare(compare_args)) = &args.command {
        return compare::run(compare_args);
    }
    if args.runs.is_some()
        || args.warmup.is_some()
        || args.workload.is_some()
        || args.output.is_some()
    {
        return harness::run(&args);
    }
    single::run(&args)
}
