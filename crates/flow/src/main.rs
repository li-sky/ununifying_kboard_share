use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(about = "Inspect and switch Logitech HID++ Easy-Switch hosts")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Inspect,
    Collections,
    Switch {
        #[arg(long, value_parser = clap::value_parser!(u8).range(0..=2))]
        host: u8,
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=6))]
        slot: Option<u8>,
    },
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::Collections => {
            for collection in kbshare_flow::collections()? {
                println!(
                    "pid={:04x} usage={:04x}:{:04x} interface={} candidate={} path={}",
                    collection.product_id,
                    collection.usage_page,
                    collection.usage,
                    collection.interface_number,
                    collection.candidate,
                    collection.path,
                );
            }
        }
        Command::Inspect => {
            let devices = kbshare_flow::inspect()?;
            if devices.is_empty() {
                bail!("no ChangeHost-capable Logitech devices found");
            }
            for device in devices {
                println!(
                    "{} pid={:04x} {:?} slot={} type={:?} hosts={} current={} feature={:02x}",
                    device.name.as_deref().unwrap_or("Logitech device"),
                    device.product_id,
                    device.connection,
                    device.slot,
                    device.device_type,
                    device.host_count,
                    device.current_host,
                    device.feature_index,
                );
            }
        }
        Command::Switch { host, slot } => {
            let device = kbshare_flow::switch_host(slot, host)?;
            println!(
                "switch sent to {} (slot {}) -> host {}",
                device.name.as_deref().unwrap_or("Logitech device"),
                device.slot,
                host,
            );
        }
    }
    Ok(())
}
