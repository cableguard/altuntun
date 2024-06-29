// Copyright (c) 2023 Cableguard, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;
pub mod api;
mod dev_lock;
pub mod drop_privileges;

#[cfg(test)]
mod integration_tests;
pub mod peer;

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "kqueue.rs"]
pub mod poll;

#[cfg(target_os = "linux")]
#[path = "epoll.rs"]
pub mod poll;

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
pub mod tun;

use tracing::error;
use std::collections::HashMap;
use std::io::{self, Write as _};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use allowed_ips::AllowedIps;
use parking_lot::Mutex;
use peer::{AllowedIP, Peer};
use poll::{EventPoll, EventRef, WaitResult};
use rand_core::{OsRng, RngCore};
use socket2::{Domain, Protocol, Type};
use tun::TunSocket;
use dev_lock::{Lock, LockReadGuard};
use crate::x25519;
use crate::noise::errors::WireGuardError;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::noise::handshake::consume_received_handshake_peer_2blisted;
const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies
const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const MAX_ITR: usize = 100; // Number of packets to handle per handler call

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    Socket(io::Error),
    #[error("{0}")]
    Bind(String),
    #[error("{0}")]
    FCntl(io::Error),
    #[error("{0}")]
    EventQueue(io::Error),
    #[error("{0}")]
    IOCtl(io::Error),
    #[error("{0}")]
    Connect(String),
    #[error("{0}")]
    SetSockOpt(String),
    #[error("Error: Invalid tunnel name")]
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[error("{0}")]
    GetSockOpt(io::Error),
    #[error("{0}")]
    GetSockName(String),
    #[cfg(target_os = "linux")]
    #[error("{0}")]
    Timer(io::Error),
    #[error("interface read: {0}")]
    IfaceRead(io::Error),
    #[error("{0}")]
    DropPrivileges(String),
    #[error("API socket error: {0}")]
    ApiSocket(io::Error),
}

// What the event loop should do after a handler returns
enum Action {
    Continue, // Continue the loop
    Yield,    // Yield the read lock and acquire it again
    Exit,     // Stop the loop
}

// Event handler function
type Handler = Box<dyn Fn(&mut LockReadGuard<Device>, &mut ThreadData) -> Action + Send + Sync>;

pub struct DeviceHandle {
    device: Arc<Lock<Device>>, // The interface this handle owns
    threads: Vec<JoinHandle<()>>,
}

//#[derive(Debug, Clone, Copy)]
#[derive(Clone)]
pub struct DeviceConfig {
    pub n_threads: usize,
    pub use_connected_socket: bool,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,
    #[cfg(target_os = "linux")]
    pub uapi_fd: i32,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            n_threads: 4,
            use_connected_socket: true,
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            #[cfg(target_os = "linux")]
            uapi_fd: -1,
        }
    }
}

pub struct Device {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    queue: Arc<EventPoll<Handler>>,
    listen_port: u16,
    fwmark: Option<u32>,
    interface: Arc<TunSocket>,
    udp4: Option<socket2::Socket>,
    udp6: Option<socket2::Socket>,
    yield_notice: Option<EventRef>,
    exit_notice: Option<EventRef>,
    peers: HashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    listbyip_peer_index: AllowedIps<Arc<Mutex<Peer>>>,
    listbysession_peer_index: HashMap<u32, Arc<Mutex<Peer>>>,
    next_peer_index: IndexLfsr,
    config: DeviceConfig,
    cleanup_paths: Vec<String>,
    mtu: AtomicUsize,
    rate_limiter: Option<Arc<RateLimiter>>,

    #[cfg(target_os = "linux")]
    uapi_fd: i32,
}

struct ThreadData {
    interface: Arc<TunSocket>,
    src_buf: [u8; MAX_UDP_SIZE],
    dst_buf: [u8; MAX_UDP_SIZE],
}

impl DeviceHandle {
    pub fn new(tunname: &str, config: &DeviceConfig) -> Result<DeviceHandle, Error> {
        let n_threads = config.n_threads;
        let mut wg_interface = Device::new(tunname, config.clone())?;
         wg_interface.open_listen_socket(0)?;

        let interface_lock = Arc::new(Lock::new(wg_interface));
        let mut threads = vec![];

        for i in 0..n_threads {
            threads.push({
                let dev = Arc::clone(&interface_lock);
                thread::spawn(move || DeviceHandle::event_loop(i, &dev))
            });
        }
        Ok(DeviceHandle {
            device: interface_lock,
            threads,
        })
    }

    pub fn wait(&mut self) {
        while let Some(thread) = self.threads.pop() {
            thread.join().unwrap();
        }
    }

    pub fn clean(&mut self) {
        for path in &self.device.read().cleanup_paths {
            // try to remove any file we created in the work dir
            let _ = std::fs::remove_file(path);
        }
    }

    fn event_loop(_i: usize, device: &Lock<Device>) {
        #[cfg(target_os = "linux")]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            interface: if _i == 0 || !device.read().config.use_multi_queue {
                // For the first thread use the original interface
                Arc::clone(&device.read().interface)
            } else {
                // For for the rest create a new interface queue
                let iface_local = Arc::new(
                    TunSocket::new(&device.read().interface.name().unwrap())
                        .unwrap()
                        .set_non_blocking()
                        .unwrap(),
                );

                device
                    .read()
                    .register_iface_handler(Arc::clone(&iface_local))
                    .ok();

                iface_local
            },
        };

        #[cfg(not(target_os = "linux"))]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            interface: Arc::clone(&device.read().interface),
        };

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = device.read().uapi_fd;

        loop {
            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let mut device_lock = device.read();
            let queue = Arc::clone(&device_lock.queue);

            loop {
                match queue.wait() {
                    WaitResult::Ok(handler) => {
                        let action = (*handler)(&mut device_lock, &mut thread_local);
                        match action {
                            Action::Continue => {}
                            Action::Yield => break,
                            Action::Exit => {
                                device_lock.trigger_exit();
                                return;
                            }
                        }
                    }
                    WaitResult::EoF(handler) => {
                        if uapi_fd >= 0 && uapi_fd == handler.fd() {
                            device_lock.trigger_exit();
                            return;
                        }
                        handler.cancel();
                    }
                    WaitResult::Error(e) => tracing::debug!(message = "Error: Poll Failed", error = ?e),
                }
            }
        }
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

impl Device {

    fn next_peer_index(&mut self) -> u32 {
        self.next_peer_index.next()
    }

    fn remove_peer(&mut self, peer_publickey_public_key: &x25519::PublicKey) {
        if let Some(peer) = self.peers.remove(peer_publickey_public_key) {
            // Found a peer to remove, now purge all references to it:
            {
                let p = peer.lock();
                p.shutdown_endpoint(); // close open udp socket and free the closure
                self.listbysession_peer_index.remove(&p.index());
            }
            self.listbyip_peer_index
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(&peer, p));

            tracing::info!("Info: Peer removed");
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn update_peer(
        &mut self,
        peer_publickey_public_key: x25519::PublicKey,
        remove: bool,
        _replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips_listed: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        // If it wasn't for keeping compability, I would remove the silly logic
        if remove {
            // Completely remove a peer
            return self.remove_peer(&peer_publickey_public_key);
        }

        // Update an existing peer
        if self.peers.get(&peer_publickey_public_key).is_some() {
            tracing::info!("Info: Peers are dinamically added and removed so it makes no sense to update them. No actions have been performed");
            return;
        }

        let next_peer_index = self.next_peer_index();
        let device_key_pair = self
        .key_pair
        .as_ref()
        .expect("Error: Self private key must be set before adding peers");

        let tunn = Tunn::new(
            device_key_pair.0.clone(), // Own X25519 private key
            peer_publickey_public_key,
            preshared_key,
            keepalive,
            next_peer_index,
            None,
        )
        .unwrap();

        // Creation and insertion of a peer
        let peer = Peer::new(tunn, next_peer_index, endpoint, allowed_ips_listed, preshared_key);

        let peer = Arc::new(Mutex::new(peer));
        self.peers.insert(peer_publickey_public_key, Arc::clone(&peer));
        self.listbysession_peer_index.insert(next_peer_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips_listed {
            self.listbyip_peer_index
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }
        tracing::info!("Info: Peer added {:?}",peer_publickey_public_key);
    }

    pub fn new(tunname: &str, config: DeviceConfig) -> Result<Device, Error> {
        let poll = EventPoll::<Handler>::new()?;

        // Create a tunnel device
        let interface = Arc::new(TunSocket::new(tunname)?.set_non_blocking()?);
        let mtu = interface.mtu()?;

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = config.uapi_fd;

        let mut device = Device {
            queue: Arc::new(poll),
            interface,
            config,
            exit_notice: Default::default(),
            yield_notice: Default::default(),
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port: Default::default(),
            next_peer_index: Default::default(),
            peers: Default::default(),
            listbysession_peer_index: Default::default(),
            listbyip_peer_index: AllowedIps::new(),
            udp4: Default::default(),
            udp6: Default::default(),
            cleanup_paths: Default::default(),
            mtu: AtomicUsize::new(mtu),
            rate_limiter: None,
            #[cfg(target_os = "linux")]
            uapi_fd,
        };

        if uapi_fd >= 0 {
            device.register_api_fd(uapi_fd)?;
        } else {
            device.register_api_handler()?;
        }
        device.register_iface_handler(Arc::clone(&device.interface))?;
        device.register_notifiers()?;
        device.register_timers()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                if tunname == "utun" {
                    std::fs::write(&name_file, device.interface.name().unwrap().as_bytes()).unwrap();
                    device.cleanup_paths.push(name_file);
                }
            }
        }

        Ok(device)
    }

    fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        // Binds the network facing interfaces
        // First close any existing open socket, and remove them from the event loop
        if let Some(s) = self.udp4.take() {
            unsafe {
                // This is safe because the event loop is not running yet
                self.queue.clear_event_by_fd(s.as_raw_fd())
            }
        };

        if let Some(s) = self.udp6.take() {
            unsafe { self.queue.clear_event_by_fd(s.as_raw_fd()) };
        }

        for peer in self.peers.values() {
            peer.lock().shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock4.set_reuse_address(true)?;
        udp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        udp_sock4.set_nonblocking(true)?;

        if port == 0 {
            // Random port was assigned
            port = udp_sock4.local_addr()?.as_socket().unwrap().port();
        }

        let udp_sock6 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock6.set_reuse_address(true)?;
        udp_sock6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        udp_sock6.set_nonblocking(true)?;

        self.register_udp_handler(udp_sock4.try_clone().unwrap())?;
        self.register_udp_handler(udp_sock6.try_clone().unwrap())?;
        self.udp4 = Some(udp_sock4);
        self.udp6 = Some(udp_sock6);

        self.listen_port = port;

        Ok(())
    }

    fn set_key_pair(&mut self, own_staticsecret_private_key: x25519::StaticSecret) {

        let own_publickey_public_key = x25519::PublicKey::from(&own_staticsecret_private_key);

        // We are using the input value of the function
        let own_key_pair = Some((own_staticsecret_private_key.clone(), own_publickey_public_key));

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&own_publickey_public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&own_publickey_public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            peer.lock().tunnel.set_static_private(
                own_staticsecret_private_key.clone(),
                own_publickey_public_key,
                Some(Arc::clone(&rate_limiter)),
            )
        }

        self.key_pair = own_key_pair;
        self.rate_limiter = Some(rate_limiter);

    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        if let Some(ref sock) = self.udp4 {
            sock.set_mark(mark)?;
        }

        if let Some(ref sock) = self.udp6 {
            sock.set_mark(mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.values() {
            if let Some(ref sock) = peer.lock().endpoint().conn {
                sock.set_mark(mark)?
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.listbysession_peer_index.clear();
        self.listbyip_peer_index.clear();
    }

    fn register_notifiers(&mut self) -> Result<(), Error> {
        let yield_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_, _| Action::Yield))?;
        self.yield_notice = Some(yield_ev);

        let exit_ev = self
            .queue
            // The exit event handler simply returns Action::Exit
            .new_notifier(Box::new(|_, _| Action::Exit))?;
        self.exit_notice = Some(exit_ev);
        Ok(())
    }

    fn register_timers(&self) -> Result<(), Error> {
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count()
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;

        self.queue.new_periodic_event(
            // Execute the timed function of every peer in the list
            Box::new(|d, t| {
                let peer_map = &d.peers;

                let (udp4, udp6) = match (d.udp4.as_ref(), d.udp6.as_ref()) {
                    (Some(udp4), Some(udp6)) => (udp4, udp6),
                    _ => return Action::Continue,
                };

                // Go over each peer and invoke the timer function
                for peer in peer_map.values() {
                    let mut p = peer.lock();
                    let endpoint_addr = match p.endpoint().addr {
                        Some(addr) => addr,
                        None => continue,
                    };

                    match p.update_timers(&mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            p.shutdown_endpoint(); // close open udp socket
                        }
                        TunnResult::Err(e) => tracing::debug!(message = "Error: Timer Failed", error = ?e),
                        TunnResult::WriteToNetwork(packet) => {
                            match endpoint_addr {
                                SocketAddr::V4(_) => {
                                    udp4.send_to(packet, &endpoint_addr.into()).ok()
                                }
                                SocketAddr::V6(_) => {
                                    udp6.send_to(packet, &endpoint_addr.into()).ok()
                                }
                            };
                        }
                        _ => panic!("Unexpected result from update_timers"),
                    };
                }
                Action::Continue
            }),
            std::time::Duration::from_millis(250),
        )?;
        Ok(())
    }

    pub(crate) fn trigger_yield(&self) {
        self.queue
            .trigger_notification(self.yield_notice.as_ref().unwrap())
    }

    pub(crate) fn trigger_exit(&self) {
        self.queue
            .trigger_notification(self.exit_notice.as_ref().unwrap())
    }

    pub(crate) fn cancel_yield(&self) {
        self.queue
            .stop_notification(self.yield_notice.as_ref().unwrap())
    }


    fn register_udp_handler(&self, udp: socket2::Socket) -> Result<(), Error> {
        self.queue.new_event(
        udp.as_raw_fd(),
        Box::new(move |devicebox, threaddata| {

                    // Handler that handles peer_2blisted packets over UDP
                    let mut iter = MAX_ITR;
                    let (own_staticsecret_private_key, own_publickey_public_key ) = devicebox.key_pair.as_ref().expect("Error: Key not set");
                    let rate_limiter = devicebox.rate_limiter.as_ref().unwrap().clone();
                    // Loop while we have packets on the peer_2blisted connection
                    // Safety: the `recv_from` implementation promises not to write uninitialised
                    // bytes to the buffer, so this casting is safe.
                    let src_buf =
                        unsafe { &mut *(&mut threaddata.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
                    while let Ok((packet_len, addr)) = udp.recv_from(src_buf) {
                        let packet = &threaddata.src_buf[..packet_len];
                        // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
                        let parsed_packet = match rate_limiter.verify_packet(
                            Some(addr.as_socket().unwrap().ip()),
                            packet,
                            &mut threaddata.dst_buf,)
                        {
                            Ok(packet) => packet,
                            Err(TunnResult::WriteToNetwork(cookie)) => {
                                let _: Result<_, _> = udp.send_to(cookie, &addr);
                                continue;
                            }
                            Err(_) => continue,
                        };

                        let peer = match parsed_packet {
                            Packet::HandshakeInit(p) => {
                                consume_received_handshake_peer_2blisted(own_staticsecret_private_key, own_publickey_public_key, &p)
                                    .ok()
                                    .and_then(|halfhandshake| {
                                        devicebox.peers.get(&x25519::PublicKey::from(halfhandshake.peer_static_public))
                                    })
                            }
                            Packet::HandshakeResponse(p) => devicebox.listbysession_peer_index.get(&(p.receiver_session_index >> 8)),
                            Packet::PacketCookieReply(p) => devicebox.listbysession_peer_index.get(&(p.receiver_session_index >> 8)),
                            Packet::PacketData(p) => devicebox.listbysession_peer_index.get(&(p.receiver_session_index >> 8)),
                        };

                        let peer = match peer {
                            None => continue,
                            Some(peer) => peer,
                        };

                        let mut p = peer.lock();
                        // We found a peer, use it to decapsulate the message
                        let mut flush = false; // Are there packets to send from the queue?
                        match p
                            .tunnel
                            .consume_verified_packet(parsed_packet, &mut threaddata.dst_buf[..])
                                {
                            TunnResult::Done => {}
                            TunnResult::Err(_) => continue,
                            TunnResult::WriteToNetwork(packet) => {
                                flush = true;
                                let _: Result<_, _> = udp.send_to(packet, &addr);
                            }
                            TunnResult::WriteToTunnelV4(packet, addr) => {
                                if p.is_allowed_ip(addr) {
                                    threaddata.interface.write4(packet);
                                }
                            }
                            TunnResult::WriteToTunnelV6(packet, addr) => {
                                if p.is_allowed_ip(addr) {
                                    threaddata.interface.write6(packet);
                                }
                            }
                        };
                        if flush {
                            // Flush pending queue
                            while let TunnResult::WriteToNetwork(packet) =
                                p.tunnel.decapsulate(None, &[], &mut threaddata.dst_buf[..])
                            {
                                let _: Result<_, _> = udp.send_to(packet, &addr);
                            }
                        }
                        // This packet was OK, that means we want to create a connected socket for this peer
                        let addr = addr.as_socket().unwrap();
                        let ip_addr = addr.ip();
                        p.set_endpoint(addr);
                        if devicebox.config.use_connected_socket {
                            if let Ok(sock) = p.connect_endpoint(devicebox.listen_port, devicebox.fwmark) {
                                devicebox.register_conn_handler(Arc::clone(peer), sock, ip_addr)
                                .unwrap();
                            }
                        }
                        iter -= 1;
                        if iter == 0 {
                            break;
                        }
            }
            Action::Continue
            }), // Box
        )?; //self.queue.new_event
    Ok(())
    } // function

    fn register_conn_handler(
        &self,
        peer: Arc<Mutex<Peer>>,
        udp: socket2::Socket,
        peer_addr: IpAddr,
    ) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |_, t| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let interface = &t.interface;
                let mut iter = MAX_ITR;

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                let src_buf =
                    unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };

                while let Ok(read_bytes) = udp.recv(src_buf) {
                    let mut flush = false;
                    let mut p = peer.lock();
                    match p.tunnel.decapsulate(
                        Some(peer_addr),
                        &t.src_buf[..read_bytes],
                        &mut t.dst_buf[..],
                    ) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => tracing::trace!("Error: Failed to decapsulate {:?}", e),
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            let _: Result<_, _> = udp.send(packet);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                interface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                interface.write6(packet);
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        while let TunnResult::WriteToNetwork(packet) =
                            p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            let _: Result<_, _> = udp.send(packet);
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_iface_handler(&self, interface: Arc<TunSocket>) -> Result<(), Error> {
        self.queue.new_event(
            interface.as_raw_fd(),
            Box::new(move |d, t| {
                // The iface_handler handles packets received from the WireGuard virtual network
                // interface. The flow is as follows:
                // * Read a packet
                // * Determine peer based on packet destination ip
                // * Encapsulate the packet for the given peer
                // * Send encapsulated packet to the peer's endpoint
                let mtu = d.mtu.load(Ordering::Relaxed);

                let udp4 = d.udp4.as_ref().expect("Not connected");
                let udp6 = d.udp6.as_ref().expect("Not connected");

                let listofpeers = &d.listbyip_peer_index;
                for _ in 0..MAX_ITR {
                    let src = match interface.read(&mut t.src_buf[..mtu]) {
                        Ok(src) => src,
                        Err(Error::IfaceRead(e)) => {
                            let ek = e.kind();
                            if ek == io::ErrorKind::Interrupted || ek == io::ErrorKind::WouldBlock {
                                break;
                            }
                            tracing::trace!("Error: Failed read on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                        Err(e) => {
                            tracing::trace!("Error: Unexpected failure on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                    };

                    let dst_addr = match Tunn::dst_address(src) {
                        Some(addr) => addr,
                        None => continue,
                    };

                    let mut peer = match listofpeers.find(dst_addr) {
                        Some(peer) => peer.lock(),
                        None => continue,
                    };

                    match peer.tunnel.encapsulate(src, &mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => {
                            tracing::debug!(message = "Error: Encapsulate Failed", error = ?e)
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            let mut endpoint = peer.endpoint_mut();
                            if let Some(conn) = endpoint.conn.as_mut() {
                                // Prefer to send using the connected socket
                                let _: Result<_, _> = conn.write(packet);
                            } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                                let _: Result<_, _> = udp4.send_to(packet, &addr.into());
                            } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                                let _: Result<_, _> = udp6.send_to(packet, &addr.into());
                            } else {
                                tracing::trace!("Error: No endpoint for connection");
                            }
                        }
                        _ => panic!("Unexpected result from encapsulate"),
                    };
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

}

/// A basic linear-feedback shift register implemented as xorshift, used to
/// distribute peer indexes across the 24-bit address space reserved for peer
/// identification.
/// The purpose is to obscure the total number of peers using the system and to
/// ensure it requires a non-trivial amount of processing power and/or samples
/// to guess other peers' indices. Anything more ambitious than this is wasted
/// with only 24 bits of space.
struct IndexLfsr {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    /// Generate a random 24-bit nonzero integer
    fn random_peer_index() -> u32 {
        const LFSR_MAX: u32 = 0xffffff; // 24-bit seed
        loop {
            let i = OsRng.next_u32() & LFSR_MAX;
            if i > 0 {
                // LFSR seed must be non-zero
                return i;
            }
        }
    }

    /// Generate the next value in the pseudorandom sequence
    fn next(&mut self) -> u32 {
        // 24-bit polynomial for randomness. This is arbitrarily chosen to
        // inject bitflips into the value.
        const LFSR_POLY: u32 = 0xd80000; // 24-bit polynomial
        let value = self.lfsr - 1; // lfsr will never have value of 0
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1u32)) & LFSR_POLY);
        assert!(self.lfsr != self.initial, "Too many peers created");
        value ^ self.mask
    }
}


impl Default for IndexLfsr {
    fn default() -> Self {
        let seed = Self::random_peer_index();
        IndexLfsr {
            initial: seed,
            lfsr: seed,
            mask: Self::random_peer_index(),
        }
    }
}
