// Copyright (c) 2024 Cableguard, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::dev_lock::LockReadGuard;
use super::drop_privileges::get_saved_ids;
use super::{AllowedIP, Device, Error, SocketAddr};
use crate::device::Action;

use crate::serialization::KeyBytes;
use crate::x25519;
use hex::encode as encode_hex;
use libc::*;
use std::fs::{create_dir, remove_file};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::Ordering;

const SOCK_DIR: &str = "/var/run/wireguard/";

fn produce_sock_dir() {
    let _ = create_dir(SOCK_DIR); // Create the directory if it does not exist

    if let Ok((saved_uid, saved_gid)) = get_saved_ids() {
        unsafe {
            let c_path = std::ffi::CString::new(SOCK_DIR).unwrap();
            // The directory is under the root user, but we want to be able to
            // delete the files there when we exit, so we need to change the owner
            chown(
                c_path.as_bytes_with_nul().as_ptr() as _,
                saved_uid,
                saved_gid,
            );
        }
    }
}

impl Device {
    /// Register the api handler for this Device. The api handler receives stream connections on a Unix socket
    /// with a known path: /var/run/wireguard/{tun_name}.sock.
    pub fn register_api_handler(&mut self) -> Result<(), Error> {
        let path = format!("{}/{}.sock", SOCK_DIR, self.interface.name()?);

        produce_sock_dir();

        let _ = remove_file(&path); // Attempt to remove the socket if already exists

        let api_listener = UnixListener::bind(&path).map_err(Error::ApiSocket)?; // Bind a new socket to the path

        self.cleanup_paths.push(path.clone());

        self.queue.new_event(
            api_listener.as_raw_fd(),
            Box::new(move |thisnetworkdevice, _| {
                // This is the closure that listens on the api unix socket
                let (api_conn, _) = match api_listener.accept() {
                    Ok(conn) => conn,
                    _ => return Action::Continue,
                };

                let mut readerbufferdevice = BufReader::new(&api_conn);
                let mut writerbufferdevice = BufWriter::new(&api_conn);
                let mut cmd = String::new();
                if readerbufferdevice.read_line(&mut cmd).is_ok() {
                    cmd.pop(); // pop the new line character
                    let status = match cmd.as_ref() {
                        // Only two commands are legal according to the protocol, get=1 and set=1.
                        "get=1" => api_get(&mut writerbufferdevice, thisnetworkdevice),
                        "set=1" => api_set(&mut readerbufferdevice, thisnetworkdevice),
                        _ => EIO,
                    };
                    // The protocol requires to return an Error code as the response, or zero on success
                    writeln!(writerbufferdevice, "errno={}\n", status).ok();
                }
                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        self.register_monitor(path)?;
        self.register_api_signal_handlers()
    }

    pub fn register_api_fd(&mut self, fd: i32) -> Result<(), Error> {
        let io_file = unsafe { UnixStream::from_raw_fd(fd) };

        self.queue.new_event(
            io_file.as_raw_fd(),
            Box::new(move |thisnetworkdevice, _| {
                // This is the closure that listens on the api file descriptor
                let mut readerbufferdevice = BufReader::new(&io_file);
                let mut writerbufferdevice = BufWriter::new(&io_file);
                let mut cmd = String::new();
                if readerbufferdevice.read_line(&mut cmd).is_ok() {
                    cmd.pop(); // pop the new line character
                    let status = match cmd.as_ref() {
                        "get=1" => api_get(&mut writerbufferdevice, thisnetworkdevice),
                        "set=1" => api_set(&mut readerbufferdevice, thisnetworkdevice),
                        _ => EIO,
                    };
                    // The protocol requires to return an Error code as the response, or zero on success
                    writeln!(writerbufferdevice, "errno={}\n", status).ok();
                } else {
                    // The remote side is likely closed; we should trigger an exit.
                    thisnetworkdevice.trigger_exit();
                    return Action::Exit;
                }
                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        Ok(())
    }

    fn register_monitor(&self, path: String) -> Result<(), Error> {
        self.queue.new_periodic_event(
            Box::new(move |thisnetworkdevice, _| {
                // This is not a very nice hack to detect if the control socket was removed
                // and exiting nicely as a result. We check every 3 seconds in a loop if the
                // file was deleted by stating it.
                // The problem is that on linux inotify can be used quite beautifully to detect
                // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
                // will require introducing new events, for no measurable benefit.
                // TODO: Could this be an issue if we restart the service too quickly?
                let path = std::path::Path::new(&path);
                if !path.exists() {
                    thisnetworkdevice.trigger_exit();
                    return Action::Exit;
                }

                // Periodically read the mtu of the interface in case it changes
                if let Ok(mtu) = thisnetworkdevice.interface.mtu() {
                    thisnetworkdevice.mtu.store(mtu, Ordering::Relaxed);
                }

                Action::Continue
            }),
            std::time::Duration::from_millis(1000),
        )?;

        Ok(())
    }

    fn register_api_signal_handlers(&self) -> Result<(), Error> {
        self.queue
            .new_signal_event(SIGINT, Box::new(move |_, _| Action::Exit))?;

        self.queue
            .new_signal_event(SIGTERM, Box::new(move |_, _| Action::Exit))?;

        Ok(())
    }
}

#[allow(unused_must_use)]
fn api_get(writerbufferdevice: &mut BufWriter<&UnixStream>, thisnetworkdevice: &Device) -> i32 {
    // get command requires an empty line, but there is no reason to be religious about it
    if let Some(ref own_static_key_pair) = thisnetworkdevice.key_pair {
        writeln!(writerbufferdevice, "own_public_key={}", encode_hex(own_static_key_pair.1.as_bytes()));
    }

    if thisnetworkdevice.listen_port != 0 {
        writeln!(writerbufferdevice, "listen_port={}", thisnetworkdevice.listen_port);
    }

    if let Some(fwmark) = thisnetworkdevice.fwmark {
        writeln!(writerbufferdevice, "fwmark={}", fwmark);
    }

    for (k, peer) in thisnetworkdevice.peers.iter() {
        let peer = peer.lock();
            writeln!(writerbufferdevice, "public_key={}", encode_hex(k.as_bytes()));

        if let Some(ref peer_preshared_key) = peer.preshared_key() {
            writeln!(writerbufferdevice, "preshared_key={}", encode_hex(peer_preshared_key));
        }

        if let Some(keepalive) = peer.persistent_keepalive() {
            writeln!(writerbufferdevice, "persistent_keepalive_interval={}", keepalive);
        }

        if let Some(ref addr) = peer.endpoint().addr {
            writeln!(writerbufferdevice, "endpoint={}", addr);
        }

        for (ip, cidr) in peer.allowed_ips_listed() {
            writeln!(writerbufferdevice, "allowed_ip={}/{}", ip, cidr);
        }

        if let Some(last_handshake_time) = peer.duration_since_last_handshake() {
            writeln!(
                writerbufferdevice,
                "last_handshake_time_sec={}",
                last_handshake_time.as_secs()
            );
            writeln!(
                writerbufferdevice,
                "last_handshake_time_nsec={}",
                last_handshake_time.subsec_nanos()
            );
        }

        let (_, tx_bytes, rx_bytes, ..) = peer.tunnel.stats();

        writeln!(writerbufferdevice, "rx_bytes={}", rx_bytes);
        writeln!(writerbufferdevice, "tx_bytes={}", tx_bytes);
    }
    0
}

fn api_set(readerbufferdevice: &mut BufReader<&UnixStream>, d: &mut LockReadGuard<Device>) -> i32 {
    d.try_writeable(
        |device| device.trigger_yield(),
        |device| {
            device.cancel_yield();

            let mut cmd = String::new();

            while readerbufferdevice.read_line(&mut cmd).is_ok() {
                cmd.pop(); // remove newline if any
                if cmd.is_empty() {
                    return 0; // Done
                }
                {
                    let parsed_cmd: Vec<&str> = cmd.split('=').collect();
                    if parsed_cmd.len() != 2 {
                        return EPROTO;
                    }

                    let (option, value) = (parsed_cmd[0], parsed_cmd[1]);

                    match option {
                        "private_key" => match value.parse::<KeyBytes>() {
                            Ok(own_static_bytes_key_pair) => {
                                device.set_key_pair(x25519::StaticSecret::from(own_static_bytes_key_pair.0))
                            }
                            Err(_) => return EINVAL,
                        },
                        "listen_port" => match value.parse::<u16>() {
                            Ok(port) => match device.open_listen_socket(port) {
                                Ok(()) => {}
                                Err(_) => return EADDRINUSE,
                            },
                            Err(_) => return EINVAL,
                        },
                        #[cfg(any(
                            target_os = "android",
                            target_os = "fuchsia",
                            target_os = "linux"
                        ))]
                        "fwmark" => match value.parse::<u32>() {
                            Ok(mark) => match device.set_fwmark(mark) {
                                Ok(()) => {}
                                Err(_) => return EADDRINUSE,
                            },
                            Err(_) => return EINVAL,
                        },
                        "replace_peers" => match value.parse::<bool>() {
                            Ok(true) => device.clear_peers(),
                            Ok(false) => {}
                            Err(_) => return EINVAL,
                        },
                        "public_key" => match value.parse::<KeyBytes>() {
                            Ok(own_static_bytes_key_pair) => {
                                return api_set_peer(
                                    readerbufferdevice,
                                    device,
                                    x25519::PublicKey::from(own_static_bytes_key_pair.0),
                                )
                            }
                            Err(_) => return EINVAL,
                        },
                        _ => return EINVAL,
                    }
                }
                cmd.clear();
            }
            0
        },
    )
    .unwrap_or(EIO)
}

fn api_set_peer(
    readerbufferdevice: &mut BufReader<&UnixStream>,
    thisnetworkdevice: &mut Device,
    peer_publickey_public_key: x25519::PublicKey,
) -> i32 {
    let mut cmd = String::new();

    let mut remove = false;
    let mut replace_ips = false;
    let mut endpoint = None;
    let mut keepalive = None;
    let mut clone_peer_publickey_public_key = peer_publickey_public_key;
    let mut preshared_key = None;

    let mut allowed_ips_listed: Vec<AllowedIP> = vec![];
    while readerbufferdevice.read_line(&mut cmd).is_ok() {
        cmd.pop(); // remove newline if any
        if cmd.is_empty() {
            thisnetworkdevice.update_peer(
                clone_peer_publickey_public_key,
                remove,
                replace_ips,
                endpoint,
                allowed_ips_listed.as_slice(),
                keepalive,
                preshared_key,
            );
            allowed_ips_listed.clear(); //clear the vector content after update
            return 0; // Done
        }
        {
            let parsed_cmd: Vec<&str> = cmd.splitn(2, '=').collect();
            if parsed_cmd.len() != 2 {
                return EPROTO;
            }
            let (option, value) = (parsed_cmd[0], parsed_cmd[1]);
            match option {
                "remove" => match value.parse::<bool>() {
                    Ok(true) => remove = true,
                    Ok(false) => remove = false,
                    Err(_) => return EINVAL,
                },
                "preshared_key" => match value.parse::<KeyBytes>() {
                    Ok(own_static_bytes_key_pair) => preshared_key = Some(own_static_bytes_key_pair.0),
                    Err(_) => return EINVAL,
                },
                "endpoint" => match value.parse::<SocketAddr>() {
                    Ok(addr) => endpoint = Some(addr),
                    Err(_) => return EINVAL,
                },
                "persistent_keepalive_interval" => match value.parse::<u16>() {
                    Ok(interval) => keepalive = Some(interval),
                    Err(_) => return EINVAL,
                },
                "replace_allowed_ips" => match value.parse::<bool>() {
                    Ok(true) => replace_ips = true,
                    Ok(false) => replace_ips = false,
                    Err(_) => return EINVAL,
                },
                "allowed_ip" => match value.parse::<AllowedIP>() {
                    Ok(ip) => allowed_ips_listed.push(ip),
                    Err(_) => return EINVAL,
                },
                "public_key" => {
                    // Indicates a new peer section
                    // Commit changes for current peer, and continue to next peer
                    thisnetworkdevice.update_peer(
                        clone_peer_publickey_public_key,
                        remove,
                        replace_ips,
                        endpoint,
                        allowed_ips_listed.as_slice(),
                        keepalive,
                        preshared_key,
                    );
                    allowed_ips_listed.clear(); //clear the vector content after update
                    match value.parse::<KeyBytes>() {
                        Ok(own_static_bytes_key_pair) => clone_peer_publickey_public_key = own_static_bytes_key_pair.0.into(),
                        Err(_) => return EINVAL,
                    }
                }
                "protocol_version" => match value.parse::<u32>() {
                    Ok(1) => {}
                    _ => return EINVAL,
                },
                _ => return EINVAL,
            }
        }
        cmd.clear();
    }
    0
}
