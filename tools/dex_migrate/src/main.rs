mod dex_types;
mod map;
mod read;
mod report;
mod write;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "netidm-dex-migrate",
    about = "Migrate user identities from dex to netidm"
)]
struct Cli {
    #[arg(long, help = "Path to dex SQLite database")]
    dex_db: String,
    #[arg(long, help = "netidm base URL (e.g. https://idm.example.com)")]
    netidm_url: String,
    #[arg(long, help = "Admin bearer token")]
    token: String,
    #[arg(
        long,
        help = "Dry run — show what would be migrated without making changes"
    )]
    dry_run: bool,
    #[arg(
        long,
        help = "List tables in the dex SQLite database and exit (useful for schema detection)"
    )]
    list_tables: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let db = read::open_db(&cli.dex_db)?;

    if cli.list_tables {
        let tables = read::list_tables(&db)?;
        println!("Tables in {}:", cli.dex_db);
        for t in &tables {
            println!("  {t}");
        }
        return Ok(());
    }

    let writer = write::NetidmWriter::new(&cli.netidm_url, &cli.token);

    let identities = read::read_user_identities(&db)?;
    tracing::info!("Read {} dex user identities", identities.len());

    let mut report = report::MigrationReport::default();

    for identity in &identities {
        match map::identity_to_provider_identity(identity) {
            Some(pi) => {
                if cli.dry_run {
                    report.would_create("ProviderIdentity", &pi.name);
                } else {
                    match writer.create_provider_identity(&pi).await {
                        Ok(()) => report.created("ProviderIdentity", &pi.name),
                        Err(e) => report.failed("ProviderIdentity", &pi.name, &e.to_string()),
                    }
                }
            }
            None => {
                tracing::warn!(dex_id = %identity.id, "Skipping unmappable identity");
            }
        }
    }

    report.print();
    Ok(())
}
