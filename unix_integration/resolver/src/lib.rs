#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use std::{fs, path::PathBuf};

#[cfg(target_family = "unix")]
#[macro_use]
extern crate tracing;
#[cfg(target_family = "unix")]
#[macro_use]
extern crate rusqlite;

#[cfg(target_family = "unix")]
pub mod db;
#[cfg(target_family = "unix")]
pub mod idprovider;
#[cfg(target_family = "unix")]
pub mod resolver;

/// Check for passwd and groups lines and return them if they're missing, this allows us to test parsing
pub fn parse_nsswitch_contents_return_missing(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            for tag in ["passwd:", "group:"] {
                if line.starts_with(tag) {
                    debug!(
                        "Found {} line in nsswitch.conf: {}",
                        tag.trim_end_matches(':'),
                        line
                    );
                    if !line.contains("netidm") {
                        warn!(
                            "nsswitch.conf {} line does not contain string 'netidm': {}",
                            tag.trim_end_matches(':'),
                            line
                        );
                        return Some(line.to_string());
                    } else {
                        debug!(
                            "nsswitch.conf {} line contains string 'netidm': {}",
                            tag.trim_end_matches(':'),
                            line
                        );
                        return None;
                    }
                }
            }
            None
        })
        .collect()
}

/// Warn the admin that user/group resolution may fail if Netidm is not configured in nsswitch.conf. This is a common misconfiguration that can lead to confusion, and is worth proactively warning about.
pub fn check_nsswitch_has_netidm(path: Option<PathBuf>) -> bool {
    // returns true if netidm is configured in nsswitch.conf, false otherwise.
    let nsswitch_conf = path.unwrap_or_else(|| PathBuf::from("/etc/nsswitch.conf"));
    if nsswitch_conf.exists() {
        match fs::read_to_string(&nsswitch_conf) {
            Ok(contents) => {
                let missing_lines = parse_nsswitch_contents_return_missing(&contents);
                if missing_lines.is_empty() {
                    debug!(
                        "{} appears to have Netidm configured OK for passwd/group resolution",
                        nsswitch_conf.display()
                    );
                    true
                } else {
                    warn!("Netidm does not appear to be configured in {} for passwd/group resolution. Lines of interest: {:?}", nsswitch_conf.display(), missing_lines);
                    false
                }
            }
            Err(err) => {
                debug!(
                    ?err,
                    "Couldn't read {} to check for Netidm presence",
                    nsswitch_conf.display()
                );
                false
            }
        }
    } else {
        debug!(
            "Couldn't read {} to check for Netidm presence - file does not exist",
            nsswitch_conf.display()
        );
        false
    }
}
