//! Looks at the kernel's routing state through herald's netlink code.
//!
//! ```text
//! netlink links                      interfaces
//! netlink addrs                      addresses
//! netlink routes [--table T] [--protocol P] [--family 4|6]
//! netlink nexthops                   nexthop objects
//! netlink lookup ADDR                the FIB entry the kernel uses for ADDR
//! netlink demo DEV                   install, move and remove routes (writes!)
//! ```
//!
//! Reading needs no privileges. `demo` changes the routing table: run it in a
//! throwaway namespace, `just netlink-demo` does that.

use std::{net::IpAddr, process::Command};

use clap::{Parser, Subcommand};
use herald_bgp::wire::Prefix;
use herald_netlink::{
    AF_INET, AF_INET6, AF_UNSPEC, Batch, Body, Link, Nexthop, RT_TABLE_MAIN, RT_TABLE_UNSPEC,
    RTPROT_BGP, Received, Route, socket::Socket,
};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Links,
    Addrs,
    Routes {
        /// 0 = all tables.
        #[arg(long, default_value_t = RT_TABLE_UNSPEC)]
        table: u32,
        /// 0 = all protocols (186 = bgp).
        #[arg(long, default_value_t = 0)]
        protocol: u8,
        #[arg(long)]
        family: Option<u8>,
    },
    Nexthops,
    Lookup {
        addr: IpAddr,
    },
    Demo {
        dev: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut socket = Socket::open()?;
    let mut batch = Batch::new(1);
    match args.command {
        Cmd::Links => {
            batch.dump_links();
        }
        Cmd::Addrs => {
            batch.dump_addresses(AF_UNSPEC);
        }
        Cmd::Routes {
            table,
            protocol,
            family,
        } => {
            let family = match family {
                None => AF_UNSPEC,
                Some(4) => AF_INET,
                Some(6) => AF_INET6,
                Some(other) => return Err(format!("family {other}: 4 or 6").into()),
            };
            batch.dump_routes(family, table, protocol);
        }
        Cmd::Nexthops => {
            batch.dump_nexthops();
        }
        Cmd::Lookup { addr } => {
            batch.lookup_route(addr);
        }
        Cmd::Demo { dev } => return demo(&mut socket, &dev),
    }
    for reply in socket.run(&batch)? {
        print_reply(&reply);
    }
    Ok(())
}

fn print_reply(reply: &Received) {
    match &reply.body {
        Ok(Body::Ack | Body::Done | Body::Other) => {}
        Ok(Body::Route(r)) => println!("{r}"),
        Ok(Body::Nexthop(n)) => println!("{n}"),
        Ok(Body::Address(a)) => println!("{a}"),
        Ok(Body::Link(l)) => println!("{l}"),
        Ok(Body::Error(e)) => println!("seq {}: error: {e}", reply.header.seq),
        Err(e) => println!("seq {}: undecodable: {e}", reply.header.seq),
    }
}

/// Sends `batch`, prints each request's answer.
fn step(socket: &mut Socket, title: &str, batch: &mut Batch) -> std::io::Result<()> {
    println!("\n== {title}");
    for r in batch.requests() {
        println!("   -> seq {} type {}", r.seq, r.kind);
    }
    for reply in socket.run(batch)? {
        let seq = reply.header.seq;
        match &reply.body {
            Ok(Body::Ack) => println!("   <- seq {seq} ACK"),
            Ok(Body::Done) => println!("   <- seq {seq} DONE"),
            Ok(Body::Error(e)) => println!("   <- seq {seq} ERROR {e}"),
            _ => {
                print!("   <- seq {seq} ");
                print_reply(&reply);
            }
        }
    }
    batch.clear();
    Ok(())
}

fn ip(args: &str) {
    let out = Command::new("sh")
        .args(["-c", &format!("ip {args}")])
        .output()
        .expect("ip");
    println!("   $ ip {args}");
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        println!("     {line}");
    }
}

fn demo(socket: &mut Socket, dev: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut batch = Batch::new(1);
    batch.dump_links();
    let link: Link = socket
        .run(&batch)?
        .into_iter()
        .find_map(|r| match r.body {
            Ok(Body::Link(l)) if l.name == dev => Some(l),
            _ => None,
        })
        .ok_or(format!("no interface {dev}"))?;
    batch.clear();
    println!("{dev} is interface {} ({link})", link.index);

    let r1: IpAddr = "10.0.0.2".parse()?;
    let r2: IpAddr = "10.0.0.3".parse()?;
    let nh = Nexthop::gateway(100, r1, link.index, RTPROT_BGP);
    let routes: Vec<Route> = ["198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/25"]
        .iter()
        .map(|p| {
            p.parse::<Prefix>()
                .map(|p| Route::via_nexthop(p, 100, RT_TABLE_MAIN, RTPROT_BGP, 20))
        })
        .collect::<Result<_, _>>()?;

    batch.add_nexthop(&nh);
    for r in &routes {
        batch.add_route(r);
    }
    println!(
        "\nOne datagram, {} bytes, {} requests:",
        batch.len(),
        batch.requests().len()
    );
    for chunk in batch.bytes().chunks(16).take(4) {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        println!("   {}", hex.join(" "));
    }
    println!("   ...");
    step(
        socket,
        "nexthop 100 via 10.0.0.2 + 3 routes using it",
        &mut batch,
    )?;
    ip("route show proto bgp");

    batch.lookup_route("198.51.100.77".parse()?);
    step(
        socket,
        "which entry does the kernel use for 198.51.100.77?",
        &mut batch,
    )?;

    batch.add_nexthop(&Nexthop::gateway(100, r2, link.index, RTPROT_BGP));
    step(
        socket,
        "failover: replace nexthop 100 -> via 10.0.0.3 (one message)",
        &mut batch,
    )?;
    ip("route show proto bgp");

    let bad = Route::via_nexthop(
        "192.0.2.128/25".parse()?,
        999,
        RT_TABLE_MAIN,
        RTPROT_BGP,
        20,
    );
    batch.add_route(&bad);
    step(
        socket,
        "a request the kernel refuses (nexthop 999 does not exist)",
        &mut batch,
    )?;

    batch.dump_routes(AF_INET, RT_TABLE_MAIN, RTPROT_BGP);
    step(
        socket,
        "dump: only table main, only proto bgp (filtered in the kernel)",
        &mut batch,
    )?;

    batch.delete_nexthop(100);
    step(
        socket,
        "delete nexthop 100 (its routes go with it)",
        &mut batch,
    )?;
    ip("route show proto bgp");
    ip("nexthop show");
    Ok(())
}
