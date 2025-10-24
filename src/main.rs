mod constants;
mod models;
mod packet_handlers;
mod upstream;

use anyhow::{Result, anyhow, bail};
use pnet::datalink;
use pnet::datalink::Channel;

use crate::constants::MITM_IFACE_NAME;
use crate::packet_handlers::EthernetHandler;

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let interfaces = datalink::interfaces();
    let selected_interface = interfaces
        .iter()
        .find(|iface| {
            log::debug!(
                "available interface: {} (mac: {:?}, ips: {:?})",
                iface.name,
                iface.mac,
                iface.ips,
            );
            iface.name == MITM_IFACE_NAME
        })
        .ok_or(anyhow!("cannot find interface {MITM_IFACE_NAME}"))?;
    let own_mac_address = selected_interface
        .mac
        .ok_or(anyhow!("cannot get mac address for interface"))?;

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
                log::trace!("received packet");

                match ethernet.handle_packet(packet, ()) {
                    Ok(Some(packet)) => {
                        if let Some(Err(e)) =
                            tx.send_to(packet.as_slice(), Some(selected_interface.to_owned()))
                        {
                            log::error!("error while sending packet: {e}");
                        }
                    }
                    Ok(None) => {
                        log::trace!("ignoring packet");
                    }
                    Err(e) => {
                        log::error!("error while handling ethernet packet: {e}");
                    }
                }
            }
            Err(e) => bail!("cannot get .next() packet: {e}"),
        }
    }
}
