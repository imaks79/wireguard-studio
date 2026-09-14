use std::path::Path;

use wgcore::{generate_private_key, HostOptions, WireGuardNetwork};

fn main() -> wgcore::Result<()> {
    let mut net = WireGuardNetwork::new();

    // A /24 for HQ's LAN + roadwarrior clients. HQ's own address (.1) is
    // reserved below so the pool never hands it out to a client.
    net.create_pool("hq-clients", "10.10.0.0/24", None, &["10.10.0.1".to_string()])?;

    // A separate /24 for the branch office's own LAN.
    net.create_pool("branch-clients", "10.10.1.0/24", None, &["10.10.1.1".to_string()])?;

    // Office gateway: public endpoint, listens on a fixed port, acts as the hub.
    net.create_host(
        "office-hq",
        HostOptions {
            address: vec!["10.10.0.1/24".into()],
            listen_port: Some(51820),
            post_up: vec![
                "iptables -A FORWARD -i wg0 -j ACCEPT".into(),
                "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE".into(),
            ],
            post_down: vec![
                "iptables -D FORWARD -i wg0 -j ACCEPT".into(),
                "iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE".into(),
            ],
            save_config: Some(false),
            table: Some("auto".into()),
            ..Default::default()
        },
        None,
    )?;

    // Second office, also has a public endpoint (site-to-site link).
    net.create_host(
        "office-branch",
        HostOptions {
            address: vec!["10.10.1.1/24".into()],
            listen_port: Some(51820),
            table: Some("auto".into()),
            ..Default::default()
        },
        None,
    )?;

    // Roadwarrior clients: no listen port needed, uses HQ's DNS.
    net.create_host(
        "client-alice",
        HostOptions {
            dns: vec!["10.10.0.1".into()],
            mtu: Some(1420),
            ..Default::default()
        },
        Some("hq-clients"),
    )?;

    // You can also supply a private key manually instead of generating
    // one, while still letting the pool assign the address:
    net.create_host(
        "client-bob",
        HostOptions {
            private_key: Some(generate_private_key()),
            dns: vec!["10.10.0.1".into()],
            ..Default::default()
        },
        Some("hq-clients"),
    )?;

    // A third client, this time on the branch office's subnet.
    net.create_host(
        "client-carol",
        HostOptions {
            dns: vec!["10.10.1.1".into()],
            ..Default::default()
        },
        Some("branch-clients"),
    )?;

    // Site-to-site: HQ <-> Branch, each routing the other's whole subnet.
    net.mesh(
        "office-hq",
        "office-branch",
        vec!["10.10.1.0/24".into()],
        vec!["10.10.0.0/24".into()],
        Some("hq.example.com:51820".into()),
        Some("branch.example.com:51820".into()),
        Some(25),
        true,
    )?;

    // Clients only need HQ as their peer, routing all traffic through it.
    // Each `get_mut(...)` below borrows `net.hosts` mutably for that call,
    // so the "other" host it needs is cloned into a local *first* --
    // indexing `net.hosts` again while that mutable borrow is still live
    // (e.g. as a call argument) is exactly the aliasing the borrow
    // checker exists to catch.
    let hq_clone = net.hosts["office-hq"].clone();
    let alice_clone = net.hosts["client-alice"].clone();
    let alice_addr = alice_clone.address[0].clone();
    net.hosts.get_mut("office-hq").unwrap().add_peer_host(
        &alice_clone,
        vec![alice_addr],
        None,
        None,
        Some(wgcore::generate_preshared_key()),
    )?;
    net.hosts.get_mut("client-alice").unwrap().add_peer_host(
        &hq_clone,
        vec!["0.0.0.0/0".into()],
        Some("hq.example.com:51820".into()),
        Some(25),
        None,
    )?;

    let bob_clone = net.hosts["client-bob"].clone();
    let bob_addr = bob_clone.address[0].clone();
    net.hosts.get_mut("office-hq").unwrap().add_peer_host(
        &bob_clone,
        vec![bob_addr],
        None,
        None,
        Some(wgcore::generate_preshared_key()),
    )?;
    net.hosts.get_mut("client-bob").unwrap().add_peer_host(
        &hq_clone,
        vec!["0.0.0.0/0".into()],
        Some("hq.example.com:51820".into()),
        Some(25),
        None,
    )?;

    // Carol connects through the branch office instead of HQ.
    let branch_clone = net.hosts["office-branch"].clone();
    let carol_clone = net.hosts["client-carol"].clone();
    let carol_addr = carol_clone.address[0].clone();
    net.hosts.get_mut("office-branch").unwrap().add_peer_host(
        &carol_clone,
        vec![carol_addr],
        None,
        None,
        Some(wgcore::generate_preshared_key()),
    )?;
    net.hosts.get_mut("client-carol").unwrap().add_peer_host(
        &branch_clone,
        vec!["0.0.0.0/0".into()],
        Some("branch.example.com:51820".into()),
        Some(25),
        None,
    )?;

    let out_dir = Path::new("./wireguard-configs");
    let paths = net.save_all(out_dir)?;

    println!("Wrote {} config files to {}/\n", paths.len(), out_dir.display());
    for p in &paths {
        println!("--- {} ---", p.display());
        println!("{}", std::fs::read_to_string(p)?);
    }

    println!("Pool status:");
    for (name, pool) in &net.pools {
        println!("  {name}: {}", pool.describe());
    }

    Ok(())
}
