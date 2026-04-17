use netidm_proto::constants::DEFAULT_CLIENT_CONFIG_PATH;
pub const DEFAULT_LDAP_CONFIG_PATH: &str = "/etc/netidm/ldap-sync";

#[derive(Debug, clap::Parser, Clone)]
#[clap(about = "Netidm LDAP Sync Driver")]
pub struct Opt {
    /// Enable debugging of the sync driver
    #[clap(short, long, env = "NETIDM_DEBUG")]
    pub debug: bool,
    /// Path to the client config file.
    #[clap(short, long, value_parser, default_value_os_t = DEFAULT_CLIENT_CONFIG_PATH.into())]
    pub client_config: PathBuf,

    /// Path to the ldap-sync config file.
    #[clap(short, long, value_parser, default_value_os_t = DEFAULT_LDAP_CONFIG_PATH.into())]
    pub ldap_sync_config: PathBuf,

    /// Dump the ldap protocol inputs, as well as the scim outputs. This can be used
    /// to create test cases for testing the parser.
    ///
    /// No actions are taken on the netidm instance, this is purely a dump of the
    /// state in/out.
    #[clap(short, long, hide = true)]
    pub proto_dump: bool,

    /// Read entries from ldap, and check the connection to netidm, but take no actions against
    /// netidm that would change state.
    #[clap(short = 'n')]
    pub dry_run: bool,

    /// Run in scheduled mode, where the sync tool will periodically attempt to sync between
    /// LDAP and Netidm.
    #[clap(long = "schedule")]
    pub schedule: bool,

    /// Skip the root user permission check.
    #[clap(short, long, hide = true)]
    pub skip_root_check: bool,
}
