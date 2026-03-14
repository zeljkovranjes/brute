/// The configuration  parameters in order to run Brute successfully.
#[derive(clap::Parser)]
pub struct Config {
    /// Database connection string.
    #[clap(long, env)]
    pub database_url: String,

    /// API token for IPinfo.io. Leave empty when using a proxy that handles
    /// auth internally via IPINFO_BASE_URL.
    #[clap(long, env, default_value = "")]
    pub ipinfo_token: String,

    /// Base URL for the IPinfo endpoint. Set to a self-hosted round-robin proxy
    /// URL to route through it instead of hitting https://ipinfo.io directly.
    /// Leave empty to use https://ipinfo.io.
    #[clap(long, env, default_value = "")]
    pub ipinfo_base_url: String,

    /// Number of days to retain attack records. Rows older than this are
    /// pruned daily at midnight UTC.
    #[arg(long, env = "DATA_RETENTION_DAYS", default_value = "90")]
    pub data_retention_days: u32,
}