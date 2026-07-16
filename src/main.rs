//! Privilege boundary for one Cloud Hypervisor process.

use std::fs::File;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod manifest;

#[cfg(target_os = "linux")]
mod linux;

use manifest::Manifest;

#[derive(Parser, Debug)]
#[command(name = "cloud-hypervisor-jailer")]
#[command(about = "Validate and launch a Cloud Hypervisor sandbox")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Validate a manifest before any privileged namespace work is attempted.
    Validate {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Establish the jail and exec Cloud Hypervisor from a validated manifest.
    Launch {
        #[arg(long)]
        manifest: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    let (manifest_path, launch_requested) = match args.command {
        Command::Validate { manifest } => (manifest, false),
        Command::Launch { manifest } => (manifest, true),
    };
    let file = File::open(&manifest_path)
        .with_context(|| format!("open manifest {}", manifest_path.display()))?;
    let manifest: Manifest = serde_json::from_reader(file).context("parse manifest")?;
    manifest.validate().context("validate manifest")?;
    if launch_requested {
        launch(&manifest)?;
    }
    Ok(())
}

fn launch(manifest: &Manifest) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::launch(manifest)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = manifest;
        anyhow::bail!("cloud-hypervisor-jailer launch is supported only on Linux")
    }
}
