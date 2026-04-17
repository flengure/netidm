use clap::Subcommand;

#[derive(Debug, Subcommand)]
#[clap(about = "Netidm Unixd Management Utility")]
pub enum NetidmUnixOpt {
    /// Test authentication of a user via the unixd resolver "pam" channel. This does not
    /// test that your pam configuration is correct - only that unixd is correctly processing
    /// and validating authentications.
    AuthTest {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: String,
    },
    /// Erase the content of the unixd resolver cache. You should probably use `invalidate`
    /// instead.
    CacheClear {
        #[clap(short, long)]
        debug: bool,
        #[clap(long)]
        really: bool,
    },
    /// Invalidate, but don't erase the content of the unixd resolver cache. This will force
    /// the unixd daemon to refresh all user and group content immediately. If the connection
    /// is offline, entries will still be available and will be refreshed as soon as the daemon
    /// is online again.
    CacheInvalidate {
        #[clap(short, long)]
        debug: bool,
    },
    /// Check that the unixd daemon is online and able to connect correctly to the netidmd server.
    Status {
        #[clap(short, long)]
        debug: bool,
    },
    /// Show the version of this tool.
    Version {
        #[clap(short, long)]
        debug: bool,
    }
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Netidm Unixd Management Utility")]
#[command(name = "netidm_unixd")]
pub struct NetidmUnixParser {
    #[clap(subcommand)]
    pub commands: NetidmUnixOpt,
}

