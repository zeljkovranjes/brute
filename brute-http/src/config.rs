/// The configuration  parameters in order to run Brute successfully.
#[derive(clap::Parser)]
pub struct Config {
    /// Database connection string.
    #[clap(long, env)]
    pub database_url: String,

    /// API token for IPinfo.io service.
    #[clap(long, env)]
    pub ipinfo_token: String,

    /// Number of days to retain attack records. Rows older than this are
    /// pruned daily at midnight UTC.
    #[arg(long, env = "DATA_RETENTION_DAYS", default_value = "90")]
    pub data_retention_days: u32,
}