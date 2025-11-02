use std::str::FromStr;

use color_eyre::{
    eyre::{bail, eyre, WrapErr},
    Result,
};
use pnet::datalink;
use pnet::datalink::Channel;
use tracing::{debug, error, trace};
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    filter::Directive, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

use crate::constants::MITM_IFACE_NAME;
use crate::packet_handlers::EthernetHandler;

mod constants;
mod models;
mod packet_handlers;
mod upstream;

fn main() -> Result<()> {
    color_eyre::install()?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .pretty()
                .with_thread_names(true)
                .with_line_number(true)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(Directive::from_str("trace")?)
                        .from_env()?,
                ),
        )
        .with(ErrorLayer::default())
        .try_init()
        .wrap_err("tracing initialization failed")?;

    let interfaces = datalink::interfaces();
    let selected_interface = interfaces
        .iter()
        .find(|iface| {
            debug!(
                "available interface: {} (mac: {:?}, ips: {:?})",
                iface.name, iface.mac, iface.ips,
            );
            iface.name == MITM_IFACE_NAME
        })
        .ok_or(eyre!("cannot find interface {MITM_IFACE_NAME}"))?;
    let own_mac_address = selected_interface
        .mac
        .ok_or(eyre!("cannot get mac address for interface"))?;

    let (mut tx, mut rx) = match datalink::channel(
        selected_interface,
        datalink::Config {
            promiscuous: true,
            read_buffer_size: 65535,
            write_buffer_size: 65535,
            ..Default::default()
        },
    ) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => bail!("wrong channel type..."),
        Err(e) => bail!("error while creating channel: {e}"),
    };

    let mut ethernet = EthernetHandler::new(own_mac_address);
    loop {
        match rx.next() {
            Ok(packet) => {
                trace!("Received packet.");

                match ethernet.handle_packet(packet, ()) {
                    Ok(Some(packet)) => {
                        if let Some(Err(e)) =
                            tx.send_to(packet.as_slice(), Some(selected_interface.to_owned()))
                        {
                            error!("Error while sending packet: {e}");
                        }
                    }
                    Ok(None) => {
                        trace!("Ignoring packet.");
                    }
                    Err(err) => {
                        error!("Error while handling ethernet packet: {err}");
                    }
                }
            }
            Err(e) => bail!("cannot get .next() packet: {e}"),
        }
    }
}
