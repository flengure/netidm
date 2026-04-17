pub enum Error {
    Io,
    SerdeToml,
    SerdeJson,
    NetidmClient,
    ProfileBuilder,
    Tokio,
    Interrupt,
    Crossbeam,
    InvalidState,
    #[allow(dead_code)]
    RandomNumber(String),
}
