use actix::{
    Actor, ActorFutureExt, AsyncContext, Context, Handler, ResponseActFuture, ResponseFuture,
    WrapFuture,
};
use ipinfo::IpInfo;
use log::{error, info};
use reporter::BruteReporter;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    error::BruteResponeError,
    model::{
        Individual, ProcessedIndividual, TopCity, TopCountry, TopHourly, TopIp, TopLocation,
        TopOrg, TopPassword, TopPostal, TopProtocol, TopRegion, TopTimezone, TopUsername,
        TopUsrPassCombo,
    },
};

// A trait that I forgot about.
pub trait Brute {}

////////////////////
// REQUEST TYPES //
//////////////////
pub struct RequestWithLimit<T> {
    pub table: T, // just call ::default()
    pub limit: usize,
    pub max_limit: usize,
}

//////////////////////
// SYSTEM /w ACTOR //
////////////////////
#[derive(Clone)]
pub struct BruteSystem {
    /// PostgreSQL connection pool.
    pub db_pool: Pool<Postgres>,

    /// IP info client with shared access.
    pub ipinfo_client: Arc<Mutex<IpInfo>>,
}

impl BruteSystem {
    /// Creates a new instance of `BruteSystem`.
    ///
    /// # Panics
    ///
    /// Panics if the provided database pool is closed.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Create the PostgreSQL connection pool
    /// let brute_config = BruteConfig::default();
    ///
    /// // Create an instance of BruteSystem
    /// let brute_system = BruteSystem::new(brute_config); // as an actor you will append .start() at the end.s
    /// ```
    pub async fn new_brute(pg_pool: Pool<Postgres>, ipinfo_client: IpInfo) -> Self {
        Self {
            db_pool: pg_pool,
            ipinfo_client: Arc::new(Mutex::new(ipinfo_client)),
        }
    }

    /// Reports data to the database.
    pub fn reporter(&self) -> BruteReporter<BruteSystem> {
        let brute_system = self.clone();
        BruteReporter::new(brute_system)
    }
}

impl Brute for BruteSystem {}

impl Actor for BruteSystem {
    type Context = Context<Self>;
}

/////////////////////////
// INDIVIDUAL MESSAGE //
///////////////////////
impl Handler<Individual> for BruteSystem {
    type Result = ResponseActFuture<Self, Result<ProcessedIndividual, BruteResponeError>>;

    fn handle(&mut self, msg: Individual, _: &mut Self::Context) -> Self::Result {
        let reporter = self.reporter();
        let fut = async move {
            match reporter.start_report(msg).await {
                Ok(result) => {
                    info!(
                        "Successfully processed Individual with ID: {}. Details: Username: '{}', IP: '{}', Protocol: '{}', Timestamp: {}, Location: {} - {}, {}, {}",
                        result.id(),
                        result.username(),
                        result.ip(),
                        result.protocol(),
                        result.timestamp(),
                        result.city().as_ref().unwrap_or(&"{EMPTY}".to_string()),
                        result.region().as_ref().unwrap_or(&"{EMPTY}".to_string()),
                        result.country().as_ref().unwrap_or(&"{EMPTY}".to_string()),
                        result.postal().as_ref().unwrap_or(&"{EMPTY}".to_string())
                    );
                    Ok(result)
                }
                Err(e) => {
                    error!("Failed to process report: {}", e);
                    Err(BruteResponeError::InternalError(
                        "something definitely broke on our side".to_string(),
                    ))
                }
            }
        };
        fut.into_actor(self).map(|res, _, _| res).boxed_local()
    }
}
/*
impl Handler<Individual> for BruteSystem {
    type Result = ();

    fn handle(&mut self, msg: Individual, ctx: &mut Self::Context) -> Self::Result {
        let reporter = self.reporter();
        async move {
                match reporter.start_report(msg).await {
                    Ok(result) => {
                        info!("Successfully processed Individual with ID: {}. Details: Username: '{}', IP: '{}', Protocol: '{}', Timestamp: {}, Location: {} - {}, {}, {}",
                            result.id(),
                            result.username(),
                            result.ip(),
                            result.protocol(),
                            result.timestamp(),
                            result.city().as_ref().unwrap_or(&"{EMPTY}".to_string()),
                            result.region().as_ref().unwrap_or(&"{EMPTY}".to_string()),
                            result.country().as_ref().unwrap_or(&"{EMPTY}".to_string()),
                            result.postal().as_ref().unwrap_or(&"{EMPTY}".to_string())
                        );
                    }
                    Err(e) => {
                        error!("Failed to process report: {}", e);
                    }
                }
            }.into_actor(self).wait(ctx)
    }
}
*/

//////////////////////////////////
// PROCESSEDINDIVIDUAL MESSAGE //
////////////////////////////////
impl Handler<RequestWithLimit<ProcessedIndividual>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<ProcessedIndividual>, BruteResponeError>>;

    fn handle(
        &mut self,
        msg: RequestWithLimit<ProcessedIndividual>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM processed_individual ORDER BY timestamp DESC LIMIT $1";
            let rows = sqlx::query_as::<_, ProcessedIndividual>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(
                    "something definitely broke on our side".to_string(),
                )),
            }
        };
        Box::pin(fut)
    }
}

///////////////////////////
// TOP USERNAME MESSAGE //
/////////////////////////
impl Handler<RequestWithLimit<TopUsername>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopUsername>, BruteResponeError>>;

    fn handle(
        &mut self,
        msg: RequestWithLimit<TopUsername>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_username ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopUsername>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(
                    "something definitely broke on our side".to_string(),
                )),
            }
        };
        Box::pin(fut)
    }
}

///////////////////////////
// TOP PASSWORD MESSAGE //
/////////////////////////
impl Handler<RequestWithLimit<TopPassword>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopPassword>, BruteResponeError>>;

    fn handle(
        &mut self,
        msg: RequestWithLimit<TopPassword>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_password WHERE password !~ '^X{2,}$' ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopPassword>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(
                    "something definitely broke on our side".to_string(),
                )),
            }
        };
        Box::pin(fut)
    }
}

/////////////////////
// TOP IP MESSAGE //
////////////////////
impl Handler<RequestWithLimit<TopIp>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopIp>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimit<TopIp>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_ip ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopIp>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(
                    "something definitely broke on our side".to_string(),
                )),
            }
        };
        Box::pin(fut)
    }
}

////////////////////////////
// TOP TOPUSRPASS MESSAGE //
////////////////////////////
impl Handler<RequestWithLimit<TopUsrPassCombo>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopUsrPassCombo>, BruteResponeError>>;

    fn handle(
        &mut self,
        msg: RequestWithLimit<TopUsrPassCombo>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_usr_pass_combo WHERE password !~ '^X{2,}$' ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopUsrPassCombo>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(
                    "something definitely broke on our side".to_string(),
                )),
            }
        };
        Box::pin(fut)
    }
}

///////////////////////////
// TOP PROTOCOL MESSAGE //
/////////////////////////
impl Handler<RequestWithLimit<TopProtocol>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopProtocol>, BruteResponeError>>;

    fn handle(
        &mut self,
        msg: RequestWithLimit<TopProtocol>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_protocol ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopProtocol>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(
                    "something definitely broke on our side".to_string(),
                )),
            }
        };
        Box::pin(fut)
    }
}

/////////////////////////////////
// INCREMENT PROTOCOL MESSAGE //
///////////////////////////////
impl Handler<TopProtocol> for BruteSystem {
    type Result = ();

    fn handle(&mut self, msg: TopProtocol, ctx: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();

        let fut = Box::pin(async move {
            let query = r#"
                INSERT INTO top_protocol ( protocol, amount )
                VALUES ($1, 1)
                ON CONFLICT (protocol)
                DO UPDATE SET amount = top_protocol.amount + EXCLUDED.amount
            "#;
            let result = sqlx::query(query)
                .bind(msg.protocol())
                .execute(&db_pool)
                .await;
            match result {
                Ok(_) => {
                    info!("Successfully incremented protocol: {}", msg.protocol())
                }
                Err(_) => {
                    error!("Failed to increment proptocol: {}", msg.protocol());
                }
            }
        });
        // Spawn the future as an actor message.
        ctx.spawn(fut.into_actor(self));
    }
}

//////////////////////////
// TOP COUNTRY MESSAGE //
////////////////////////
impl Handler<RequestWithLimit<TopCountry>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopCountry>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimit<TopCountry>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_country ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopCountry>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(
                    "a country broke the server.".to_string(),
                )),
            }
        };
        Box::pin(fut)
    }
}

///////////////////////
// TOP CITY MESSAGE //
/////////////////////
impl Handler<RequestWithLimit<TopCity>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopCity>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimit<TopCity>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_city ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopCity>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(format!(
                    "some city in {} broke the server",
                    msg.table.city()
                ))),
            }
        };
        Box::pin(fut)
    }
}

/////////////////////////
// TOP REGION MESSAGE //
///////////////////////
impl Handler<RequestWithLimit<TopRegion>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopRegion>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimit<TopRegion>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_region ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopRegion>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(format!(
                    "how did some region named {} break the server",
                    msg.table.region()
                ))),
            }
        };
        Box::pin(fut)
    }
}

///////////////////////////
// TOP TIMEZONE MESSAGE //
/////////////////////////
impl Handler<RequestWithLimit<TopTimezone>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopTimezone>, BruteResponeError>>;

    fn handle(
        &mut self,
        msg: RequestWithLimit<TopTimezone>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_timezone ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopTimezone>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(format!(
                    "this timezone? really. {} break the server",
                    msg.table.timezone()
                ))),
            }
        };
        Box::pin(fut)
    }
}

///////////////////////////////
// TOP ORGANIZATION MESSAGE //
/////////////////////////////
impl Handler<RequestWithLimit<TopOrg>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopOrg>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimit<TopOrg>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_org ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopOrg>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(format!(
                    "how did some org named {} break the server",
                    msg.table.org()
                ))),
            }
        };
        Box::pin(fut)
    }
}

/////////////////////////
// TOP POSTAL MESSAGE //
///////////////////////
impl Handler<RequestWithLimit<TopPostal>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopPostal>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimit<TopPostal>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query =
                "SELECT * FROM top_postal WHERE postal !~ '^\\s*$' ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopPostal>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(format!(
                    "how did some postal code with this code {} break the server",
                    msg.table.postal()
                ))),
            }
        };
        Box::pin(fut)
    }
}

///////////////////////////
// TOP LOCATION MESSAGE //
/////////////////////////
impl Handler<RequestWithLimit<TopLocation>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopLocation>, BruteResponeError>>;

    fn handle(
        &mut self,
        msg: RequestWithLimit<TopLocation>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_loc ORDER BY amount DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopLocation>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(
                    "something definitely broke on our side".to_string(),
                )),
            }
        };
        Box::pin(fut)
    }
}

/////////////////
// TOP HOURLY //
///////////////
impl Handler<RequestWithLimit<TopHourly>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopHourly>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimit<TopHourly>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;

        let fut = async move {
            let query = "SELECT * FROM top_hourly ORDER BY timestamp DESC LIMIT $1;";
            let rows = sqlx::query_as::<_, TopHourly>(query)
                .bind(limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError(
                    "something definitely broke on our side".to_string(),
                )),
            }
        };
        Box::pin(fut)
    }
}

///////////////
// REPORTER //
/////////////

pub mod reporter {
    use super::{Brute, BruteSystem};
    use crate::model::{
        Individual, ProcessedIndividual, TopCity, TopCountry, TopDaily, TopHourly, TopIp,
        TopLocation, TopOrg, TopPassword, TopPostal, TopProtocol, TopRegion, TopTimezone,
        TopUsername, TopUsrPassCombo, TopWeekly, TopYearly,
    };
    use ipinfo::{AbuseDetails, AsnDetails, CompanyDetails, DomainsDetails, PrivacyDetails};
    use log::info;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::Instant;
    use uuid::Uuid;

    pub trait Reporter {}

    // todo take Pool<Postgres> instead of the entire struct
    // so only the pool is getting cloned and not the entire struct.
    #[allow(async_fn_in_trait)]
    pub trait Reportable<T: Reporter, R> {
        async fn report<'a>(reporter: &T, model: &'a R) -> anyhow::Result<Self>
        where
            Self: Sized;
    }

    #[derive(Clone)]
    pub struct BruteReporter<T: Brute> {
        brute: T,
    }

    impl BruteReporter<BruteSystem> {
        pub fn new(brute: BruteSystem) -> Self {
            BruteReporter { brute }
        }

        // could be refractored heavily find a way to not clone the entire struct.
        pub async fn start_report(
            &self,
            payload: Individual,
        ) -> anyhow::Result<ProcessedIndividual> {
            let start = Instant::now();
            let transaction = self.brute.db_pool.begin().await.unwrap();
            // Report individual
            let individual = Individual::report(self, &payload).await?;

            // Report processed individual
            let processed_individual = ProcessedIndividual::report(self, &individual).await?;

            // Report top statistics
            TopUsername::report(self, &individual).await?;
            TopPassword::report(self, &individual).await?;
            TopIp::report(self, &individual).await?;
            TopProtocol::report(self, &individual).await?;

            // Report location details
            TopCity::report(self, &processed_individual).await?;
            TopRegion::report(self, &processed_individual).await?;
            TopCountry::report(self, &processed_individual).await?;
            TopTimezone::report(self, &processed_individual).await?;
            TopOrg::report(self, &processed_individual).await?;
            TopPostal::report(self, &processed_individual).await?;
            TopLocation::report(self, &processed_individual).await?;

            // Report combination and time-based statistics
            TopUsrPassCombo::report(self, &individual).await?;
            TopHourly::report(self, &0).await?;
            TopDaily::report(self, &0).await?;
            TopWeekly::report(self, &0).await?;
            TopYearly::report(self, &0).await?;

            let elasped_time = start.elapsed();
            info!(
                "Successfully processed individual report in {:.2?}.",
                elasped_time
            );
            transaction.commit().await.unwrap();
            Ok(processed_individual)
        }
    }

    impl Reporter for BruteReporter<BruteSystem> {}

    ///////////
    // DATA //
    /////////

    // individual
    impl Reportable<BruteReporter<BruteSystem>, Individual> for Individual {
        async fn report<'a>(
            reporter: &BruteReporter<BruteSystem>,
            model: &'a Individual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            let query = r#"
                INSERT INTO individual (id, username, password, ip, protocol, timestamp)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
            "#;

            // Generate new ID and timestamp for the new instance
            let new_id = Uuid::new_v4().as_simple().to_string();
            let new_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            // Execute the query and get the inserted data
            let inserted = sqlx::query_as::<_, Individual>(query)
                .bind(&new_id)
                .bind(model.username())
                .bind(model.password())
                .bind(model.ip())
                .bind(model.protocol())
                .bind(new_timestamp)
                .fetch_one(pool)
                .await?;

            Ok(inserted)
        }
    }

    // processed individual
    impl Reportable<BruteReporter<BruteSystem>, Individual> for ProcessedIndividual {
        async fn report<'a>(
            reporter: &BruteReporter<BruteSystem>,
            model: &'a Individual,
        ) -> anyhow::Result<ProcessedIndividual> {
            let pool = &reporter.brute.db_pool;
            let ipinfo = &reporter.brute.ipinfo_client;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

            let select_query = "
            SELECT * FROM processed_individual
            WHERE ip = $1
            ORDER BY timestamp DESC
            LIMIT 1;
            ";

            let insert_query = "
            INSERT INTO processed_individual (
                id, username, password, ip, protocol, hostname, city, region, country, loc, org, postal,
                asn, asn_name, asn_domain, asn_route, asn_type,
                company_name, company_domain, company_type,
                vpn, proxy, tor, relay, hosting, service,
                abuse_address, abuse_country, abuse_email, abuse_name, abuse_network, abuse_phone,
                domain_ip, domain_total, domains, timestamp, timezone
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                $13, $14, $15, $16, $17,
                $18, $19, $20,
                $21, $22, $23, $24, $25, $26,
                $27, $28, $29, $30, $31, $32,
                $33, $34, $35, $36, $37
            ) RETURNING *;
            ";

            // Default values for IP details
            let asn_default = AsnDetails {
                asn: String::default(),
                name: String::default(),
                domain: String::default(),
                route: String::default(),
                asn_type: String::default(),
            };

            let company_default = CompanyDetails {
                name: String::default(),
                domain: String::default(),
                company_type: String::default(),
            };

            let abuse_default = AbuseDetails {
                address: String::default(),
                country: String::default(),
                email: String::default(),
                name: String::default(),
                network: String::default(),
                phone: String::default(),
            };

            let privacy_default = PrivacyDetails {
                vpn: false,
                proxy: false,
                tor: false,
                relay: false,
                hosting: false,
                service: String::default(),
            };

            let domain_default = DomainsDetails {
                ip: Some(String::default()),
                total: 0,
                domains: Vec::default(),
            };

            let ip_exists = sqlx::query_as::<_, ProcessedIndividual>(select_query)
                .bind(model.ip())
                .fetch_optional(pool)
                .await?;

            let mut ipinfo_lock = ipinfo.lock().await;
            let ip_details = match ip_exists {
                Some(mut result) if now - result.timestamp <= 300_000 => {
                    if result.postal().is_none() {
                        // fix unwrap error.
                        result.postal = Some(String::default())
                    }
                    info!("Reusing cached results for IP: {}", model.ip());
                    sqlx::query_as::<_, ProcessedIndividual>(insert_query)
                        .bind(model.id())
                        .bind(model.username())
                        .bind(model.password())
                        .bind(model.ip())
                        .bind(model.protocol())
                        .bind(result.hostname())
                        .bind(result.city())
                        .bind(result.region())
                        .bind(result.country())
                        .bind(result.loc())
                        .bind(result.org())
                        .bind(result.postal())
                        .bind(result.asn())
                        .bind(result.asn_name())
                        .bind(result.asn_domain())
                        .bind(result.asn_route())
                        .bind(result.asn_type())
                        .bind(result.company_name())
                        .bind(result.company_domain())
                        .bind(result.company_type())
                        .bind(result.vpn())
                        .bind(result.proxy())
                        .bind(result.tor())
                        .bind(result.relay())
                        .bind(result.hosting())
                        .bind(result.service())
                        .bind(result.abuse_address())
                        .bind(result.abuse_country())
                        .bind(result.abuse_email())
                        .bind(result.abuse_name())
                        .bind(result.abuse_network())
                        .bind(result.abuse_phone())
                        .bind(result.domain_ip())
                        .bind(result.domain_total().unwrap())
                        .bind(result.domains())
                        .bind(model.timestamp)
                        .bind(result.timezone())
                        .fetch_one(pool)
                        .await?;
                    result
                }
                _ => {
                    info!("Fetching new details from ipinfo for IP: {}", model.ip());
                    let mut ip_details = ipinfo_lock.lookup(model.ip()).await?;

                    let asn_details = ip_details.asn.as_ref().unwrap_or(&asn_default);
                    let company_details = ip_details.company.as_ref().unwrap_or(&company_default);
                    let abuse_details = ip_details.abuse.as_ref().unwrap_or(&abuse_default);
                    let domain_details = ip_details.domains.as_ref().unwrap_or(&domain_default);
                    let privacy_details = ip_details.privacy.as_ref().unwrap_or(&privacy_default);
                    if ip_details.postal.is_none() {
                        // fix unwrap error.
                        ip_details.postal = Some(String::default())
                    }

                    // Insert the new details
                    sqlx::query_as::<_, ProcessedIndividual>(insert_query)
                        .bind(model.id())
                        .bind(model.username())
                        .bind(model.password())
                        .bind(model.ip())
                        .bind(model.protocol())
                        .bind(&ip_details.hostname)
                        .bind(&ip_details.city)
                        .bind(&ip_details.region)
                        .bind(&ip_details.country)
                        .bind(&ip_details.loc)
                        .bind(&ip_details.org)
                        .bind(&ip_details.postal)
                        .bind(&asn_details.asn)
                        .bind(&asn_details.name)
                        .bind(&asn_details.domain)
                        .bind(&asn_details.route)
                        .bind(&asn_details.asn_type)
                        .bind(&company_details.name)
                        .bind(&company_details.domain)
                        .bind(&company_details.company_type)
                        .bind(privacy_details.vpn)
                        .bind(privacy_details.proxy)
                        .bind(privacy_details.tor)
                        .bind(privacy_details.relay)
                        .bind(privacy_details.hosting)
                        .bind(&privacy_details.service)
                        .bind(&abuse_details.address)
                        .bind(&abuse_details.country)
                        .bind(&abuse_details.email)
                        .bind(&abuse_details.name)
                        .bind(&abuse_details.network)
                        .bind(&abuse_details.phone)
                        .bind(&domain_details.ip)
                        .bind(domain_details.total as i64)
                        .bind(&domain_details.domains)
                        .bind(model.timestamp)
                        .bind(&ip_details.timezone)
                        .fetch_one(pool)
                        .await?
                }
            };

            Ok(ip_details)
        }
    }

    // top username
    impl Reportable<BruteReporter<BruteSystem>, Individual> for TopUsername {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &Individual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_username ( username, amount )
                VALUES ($1, 1)
                ON CONFLICT (username)
                DO UPDATE SET amount = top_username.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopUsername>(query)
                .bind(model.username())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    // top password
    impl Reportable<BruteReporter<BruteSystem>, Individual> for TopPassword {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &Individual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_password ( password, amount )
                VALUES ($1, 1)
                ON CONFLICT (password)
                DO UPDATE SET amount = top_password.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopPassword>(query)
                .bind(model.password())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    // top ip
    impl Reportable<BruteReporter<BruteSystem>, Individual> for TopIp {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &Individual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_ip ( ip, amount )
                VALUES ($1, 1)
                ON CONFLICT (ip)
                DO UPDATE SET amount = top_ip.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopIp>(query)
                .bind(model.ip())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    // top protocol
    impl Reportable<BruteReporter<BruteSystem>, Individual> for TopProtocol {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &Individual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_protocol ( protocol, amount )
                VALUES ($1, 1)
                ON CONFLICT (protocol)
                DO UPDATE SET amount = top_protocol.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopProtocol>(query)
                .bind(model.protocol())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    // top city
    impl Reportable<BruteReporter<BruteSystem>, ProcessedIndividual> for TopCity {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &ProcessedIndividual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_city (city, country, amount)
                VALUES ($1, $2, 1)
                ON CONFLICT (city, country)
                DO UPDATE SET amount = top_city.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopCity>(query)
                .bind(model.city())
                .bind(model.country())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    // top region
    impl Reportable<BruteReporter<BruteSystem>, ProcessedIndividual> for TopRegion {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &ProcessedIndividual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_region (region, country, amount)
                VALUES ($1, $2, 1)
                ON CONFLICT (region, country)
                DO UPDATE SET amount = top_region.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopRegion>(query)
                .bind(model.region())
                .bind(model.country())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    // top timezone
    impl Reportable<BruteReporter<BruteSystem>, ProcessedIndividual> for TopTimezone {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &ProcessedIndividual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_timezone ( timezone, amount )
                VALUES ($1, 1)
                ON CONFLICT (timezone)
                DO UPDATE SET amount = top_timezone.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopTimezone>(query)
                .bind(model.timezone())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    // top country
    impl Reportable<BruteReporter<BruteSystem>, ProcessedIndividual> for TopCountry {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &ProcessedIndividual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_country ( country, amount )
                VALUES ($1, 1)
                ON CONFLICT (country)
                DO UPDATE SET amount = top_country.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopCountry>(query)
                .bind(model.country())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    // top org
    impl Reportable<BruteReporter<BruteSystem>, ProcessedIndividual> for TopOrg {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &ProcessedIndividual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_org ( org, amount )
                VALUES ($1, 1)
                ON CONFLICT (org)
                DO UPDATE SET amount = top_org.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopOrg>(query)
                .bind(model.org())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    // top postal
    impl Reportable<BruteReporter<BruteSystem>, ProcessedIndividual> for TopPostal {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &ProcessedIndividual,
        ) -> anyhow::Result<Self> {
            if model.postal().is_none() {
                info!(
                    "top_postal not updated as no postal information was found. for: {}",
                    model.id()
                );
                return Ok(TopPostal::new(String::default(), 0));
            }
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_postal ( postal, amount )
                VALUES ($1, 1)
                ON CONFLICT (postal)
                DO UPDATE SET amount = top_postal.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopPostal>(query)
                .bind(model.postal())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    // top postal
    impl Reportable<BruteReporter<BruteSystem>, ProcessedIndividual> for TopLocation {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &ProcessedIndividual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_loc ( loc, amount )
                VALUES ($1, 1)
                ON CONFLICT (loc)
                DO UPDATE SET amount = top_loc.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopLocation>(query)
                .bind(model.loc())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    impl Reportable<BruteReporter<BruteSystem>, Individual> for TopUsrPassCombo {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &Individual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            // query
            let query = r#"
                INSERT INTO top_usr_pass_combo (
                    id, username, password, amount
                ) VALUES (
                    $1, $2, $3, 1
                )
                ON CONFLICT (username, password)
                DO UPDATE SET amount = top_usr_pass_combo.amount + EXCLUDED.amount
                RETURNING *;
            "#;
            let result = sqlx::query_as::<_, TopUsrPassCombo>(query)
                .bind(Uuid::new_v4().as_simple().to_string())
                .bind(model.username())
                .bind(model.password())
                .fetch_one(pool)
                .await?;
            Ok(result)
        }
    }

    impl Reportable<BruteReporter<BruteSystem>, i64> for TopHourly {
        async fn report(reporter: &BruteReporter<BruteSystem>, _: &i64) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow::anyhow!("Failed to get system time: {}", e))?
                .as_millis() as i64;

            let select_query = r#"
                SELECT *
                FROM top_hourly
                ORDER BY timestamp DESC
                LIMIT 1;
            "#;

            let top_hourly = sqlx::query_as::<_, TopHourly>(select_query)
                .fetch_optional(pool)
                .await?;

            match top_hourly {
                Some(record) if now - record.timestamp > 3_600_000 => {
                    // Insert new record if it exceeds an hour
                    let insert_query = r#"
                        INSERT INTO top_hourly (timestamp, amount)
                        VALUES ($1, 1);
                    "#;
                    sqlx::query(insert_query).bind(now).execute(pool).await?;

                    Ok(TopHourly {
                        timestamp: now,
                        amount: 1,
                    })
                }
                Some(mut record) => {
                    // Update existing record within the hour
                    record.amount += 1;
                    let update_query = r#"
                        UPDATE top_hourly
                        SET amount = $1
                        WHERE timestamp = $2;
                    "#;
                    sqlx::query(update_query)
                        .bind(record.amount)
                        .bind(record.timestamp)
                        .execute(pool)
                        .await?;

                    Ok(record)
                }
                None => {
                    // Insert a new record if none exists
                    let insert_query = r#"
                        INSERT INTO top_hourly (timestamp, amount)
                        VALUES ($1, 1);
                    "#;
                    sqlx::query(insert_query).bind(now).execute(pool).await?;

                    Ok(TopHourly {
                        timestamp: now,
                        amount: 1,
                    })
                }
            }
        }
    }

    impl Reportable<BruteReporter<BruteSystem>, i64> for TopDaily {
        async fn report(reporter: &BruteReporter<BruteSystem>, _: &i64) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow::anyhow!("Failed to get system time: {}", e))?
                .as_millis() as i64;

            let select_query = r#"
            SELECT *
            FROM top_daily
            ORDER BY timestamp DESC
            LIMIT 1;
        "#;

            let top_daily = sqlx::query_as::<_, TopDaily>(select_query)
                .fetch_optional(pool)
                .await?;

            match top_daily {
                Some(record) if now - record.timestamp > 86_400_000 => {
                    // Insert new record if it exceeds a day
                    let insert_query = r#"
                    INSERT INTO top_daily (timestamp, amount)
                    VALUES ($1, 1);
                "#;
                    sqlx::query(insert_query).bind(now).execute(pool).await?;

                    Ok(TopDaily {
                        timestamp: now,
                        amount: 1,
                    })
                }
                Some(mut record) => {
                    // Update existing record within the day
                    record.amount += 1;
                    let update_query = r#"
                    UPDATE top_daily
                    SET amount = $1
                    WHERE timestamp = $2;
                "#;
                    sqlx::query(update_query)
                        .bind(record.amount)
                        .bind(record.timestamp)
                        .execute(pool)
                        .await?;

                    Ok(record)
                }
                None => {
                    // Insert a new record if none exists
                    let insert_query = r#"
                    INSERT INTO top_daily (timestamp, amount)
                    VALUES ($1, 1);
                "#;
                    sqlx::query(insert_query).bind(now).execute(pool).await?;

                    Ok(TopDaily {
                        timestamp: now,
                        amount: 1,
                    })
                }
            }
        }
    }

    impl Reportable<BruteReporter<BruteSystem>, i64> for TopWeekly {
        async fn report(reporter: &BruteReporter<BruteSystem>, _: &i64) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow::anyhow!("Failed to get system time: {}", e))?
                .as_millis() as i64;

            let select_query = r#"
                SELECT *
                FROM top_weekly
                ORDER BY timestamp DESC
                LIMIT 1;
            "#;

            let top_weekly = sqlx::query_as::<_, TopWeekly>(select_query)
                .fetch_optional(pool)
                .await?;

            match top_weekly {
                Some(record) if now - record.timestamp > 604_800_000 => {
                    // Insert new record if it exceeds a week
                    let insert_query = r#"
                        INSERT INTO top_weekly (timestamp, amount)
                        VALUES ($1, 1);
                    "#;
                    sqlx::query(insert_query).bind(now).execute(pool).await?;

                    Ok(TopWeekly {
                        timestamp: now,
                        amount: 1,
                    })
                }
                Some(mut record) => {
                    // Update existing record within the week
                    record.amount += 1;
                    let update_query = r#"
                        UPDATE top_weekly
                        SET amount = $1
                        WHERE timestamp = $2;
                    "#;
                    sqlx::query(update_query)
                        .bind(record.amount)
                        .bind(record.timestamp)
                        .execute(pool)
                        .await?;

                    Ok(record)
                }
                None => {
                    // Insert a new record if none exists
                    let insert_query = r#"
                        INSERT INTO top_weekly (timestamp, amount)
                        VALUES ($1, 1);
                    "#;
                    sqlx::query(insert_query).bind(now).execute(pool).await?;

                    Ok(TopWeekly {
                        timestamp: now,
                        amount: 1,
                    })
                }
            }
        }
    }

    impl Reportable<BruteReporter<BruteSystem>, i64> for TopYearly {
        async fn report(reporter: &BruteReporter<BruteSystem>, _: &i64) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow::anyhow!("Failed to get system time: {}", e))?
                .as_millis() as i64;

            let select_query = r#"
                SELECT *
                FROM top_yearly
                ORDER BY timestamp DESC
                LIMIT 1;
            "#;

            let top_yearly = sqlx::query_as::<_, TopYearly>(select_query)
                .fetch_optional(pool)
                .await?;

            match top_yearly {
                Some(record) if now - record.timestamp > 31_556_800_000 => {
                    // Insert new record if it exceeds a year
                    let insert_query = r#"
                        INSERT INTO top_yearly (timestamp, amount)
                        VALUES ($1, 1);
                    "#;
                    sqlx::query(insert_query).bind(now).execute(pool).await?;

                    Ok(TopYearly {
                        timestamp: now,
                        amount: 1,
                    })
                }
                Some(mut record) => {
                    // Update existing record within the year
                    record.amount += 1;
                    let update_query = r#"
                        UPDATE top_yearly
                        SET amount = $1
                        WHERE timestamp = $2;
                    "#;
                    sqlx::query(update_query)
                        .bind(record.amount)
                        .bind(record.timestamp)
                        .execute(pool)
                        .await?;

                    Ok(record)
                }
                None => {
                    // Insert a new record if none exists
                    let insert_query = r#"
                        INSERT INTO top_yearly (timestamp, amount)
                        VALUES ($1, 1);
                    "#;
                    sqlx::query(insert_query).bind(now).execute(pool).await?;

                    Ok(TopYearly {
                        timestamp: now,
                        amount: 1,
                    })
                }
            }
        }
    }
}
