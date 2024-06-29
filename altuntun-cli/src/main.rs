// Copyright (c) 2023 Cableguard, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use clap::{Arg, Command};
use altuntun::device::{DeviceConfig, DeviceHandle};
use altuntun::device::drop_privileges::drop_privileges;
// use daemonize::Daemonize;
use daemonize::{Daemonize, Outcome};
use std::os::unix::net::UnixDatagram;
use std::process::exit;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind};
use std::env;
use tracing::{Level};

fn check_tun_name(_v: String) -> Result<(), String> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    {
        if boringtun::device::tun::parse_utun_name(&_v).is_ok() {
            Ok(())
        } else {
            Err("Tunnel name must have the format 'utun[0-9]+', use 'utun' for automatic assignment".to_owned())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

fn main() {
    let matches = Command::new("altuntun")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Vicente Aceituno Canal <vicente@cableguard.org> and Vlad Krasnov <vlad@cloudflare.com> et al, based on Wireguard (C) by Jason Donefeld")
        .args(&[
            Arg::new("INTERFACE_NAME")
                .required(true)
                .takes_value(true)
                .validator(|tunname| check_tun_name(tunname.to_string()))
                .help("The name of the created interface"),
            Arg::new("foreground")
                .long("foreground")
                .short('f')
                .help("Run and log in the foreground"),
            Arg::new("threads")
                .takes_value(true)
                .long("threads")
                .short('t')
                .env("WG_THREADS")
                .help("Number of OS threads to use")
                .default_value("4"),
            Arg::new("verbosity")
                .takes_value(true)
                .long("verbosity")
                .short('v')
                .env("WG_LOG_LEVEL")
                .possible_values(["error", "info", "debug", "trace"])
                .help("Log verbosity")
                .default_value("error"),
            Arg::new("uapi-fd")
                .long("uapi-fd")
                .env("WG_UAPI_FD")
                .help("File descriptor for the user API")
                .default_value("-1"),
                // CG: This probably needs to be tested and may be removed as tun devices are named and created internally
            Arg::new("tun-fd")
                .long("tun-fd")
                .env("WG_TUN_FD")
                .help("File descriptor for an already-existing TUN device")
                .default_value("-1"),
            Arg::new("log")
                .takes_value(true)
                .long("log")
                .short('l')
                .env("WG_LOG_FILE")
                .help("Log file")
                .default_value("/tmp/altuntun.out"),
            Arg::new("disable-drop-privileges")
                .long("disable-drop-privileges")
                .env("WG_SUDO")
                .help("Do not drop sudo privileges"),
            Arg::new("disable-connected-udp")
                .long("disable-connected-udp")
                .help("Disable connected UDP sockets to each peer"),
            #[cfg(target_os = "linux")]
            Arg::new("disable-multi-queue")
                .long("disable-multi-queue")
                .help("Disable using multiple queues for the tunnel interface"),
        ])
        .get_matches();

    let background = !matches.is_present("foreground");

    // Enable for tracing in main
    /*
    let subscriber = FmtSubscriber::builder()
    .with_max_level(Level::TRACE)
    .finish();
    tracing::subscriber::set_global_default(subscriber)
    .expect("Error: Failed to set subscriber");
    */

    #[cfg(target_os = "linux")]
    let uapi_fd: i32 = matches.value_of_t("uapi-fd").unwrap_or_else(|e| e.exit());
    let tun_fd: isize = matches.value_of_t("tun-fd").unwrap_or_else(|e| e.exit());
    let mut tun_name = matches.value_of("INTERFACE_NAME").unwrap();
    if tun_fd >= 0 {
        tun_name = matches.value_of("tun-fd").unwrap();
    }
    let n_threads: usize = matches.value_of_t("threads").unwrap_or_else(|e| e.exit());
    let log_level: Level = matches.value_of_t("verbosity").unwrap_or_else(|e| e.exit());

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);

    let _guard;

    if background {
        // Running in background mode
        let log = matches.value_of("log").unwrap();

        // Check if the log file exists, open it in append mode if it does
        // Otherwise, create a new log file
        let log_file = if let Ok(metadata) = std::fs::metadata(&log) {
            if metadata.is_file() {
                OpenOptions::new().append(true).open(&log)
            } else {
                Err(io::Error::new(
                    ErrorKind::Other,
                    format!("{} is not a regular file.", log),
                ))
            }
        } else {
            File::create(&log)
        }
        .unwrap_or_else(|err| panic!("Error: Failed to open log file {}: {}", log, err));

        // Create a non-blocking log writer and get a guard to prevent dropping it
        let (non_blocking, guard) = tracing_appender::non_blocking(log_file);
        _guard = guard;

        // Initialize the logging system with the configured log level and writer
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();

        // daemonize 0.5.0 version
            // Create a daemon process and configure it
            let daemonize = Daemonize::new().working_directory("/tmp");
            match daemonize.execute() {
                Outcome::Parent(Ok(_)) => {
                    // In parent process, child forked ok
                    let mut b = [0u8; 1];
                    if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                        println!("Info: Altuntun started successfully");
                        exit(0);
                    } else {
                         println!("Error: Altuntun Failed to start. Check if the capabilities are set and you are running with enough privileges.");
                        exit(1);
                    }
                }
                Outcome::Parent(Err(_e)) => {
                    println!("Error: Altuntun Failed to start. Check if the capabilities are set and you are running with enough privileges.");
                    exit(1);
                 }
                Outcome::Child(_) => {
                    // In child process, we'll continue below with code that is common with foreground exec
                    println!("Info: Altuntun started successfully");
                }
            }

    } else {
        // Running in foreground mode
        tracing_subscriber::fmt()
            .pretty()
            .with_max_level(log_level)
            .init();
    }

    let config = DeviceConfig {
        n_threads,
        #[cfg(target_os = "linux")]
        uapi_fd,
        use_connected_socket: !matches.is_present("disable-connected-udp"),
        #[cfg(target_os = "linux")]
        use_multi_queue: !matches.is_present("disable-multi-queue"),
    };

    // Initialize the device handle with the specified tunnel name and configuration
    let mut device_handle: DeviceHandle = match DeviceHandle::new(&tun_name, &config) {
        Ok(d) => d,
        Err(e) => {
            // Failed to notify parent problem with tunnel initiation
            tracing::trace!(message = "Error: Failed to initialize tunnel. Check if you are running with sudo", error=?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    };

    if !matches.is_present("disable-drop-privileges") {
        // Drop privileges if not disabled
        if let Err(e) = drop_privileges() {
            tracing::trace!(message = "Error: Failed to drop privileges", error = ?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    }

    // Notify parent that tunnel initiation success
    sock1.send(&[1]).unwrap();
    drop(sock1);

    println!("Info: Altuntun will hand over to TUN handle");

    // Wait for the device handle to finish processing
    device_handle.wait();
}
