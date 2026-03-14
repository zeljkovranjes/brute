use actix::{
    Actor, ActorFutureExt, AsyncContext, Context, Handler, ResponseActFuture, ResponseFuture,
    WrapFuture,
};
use crate::geo::ipinfo::IpInfoProvider;
use log::{error, info};
use reporter::BruteReporter;
use sqlx::{Pool, Postgres};
use std::sync::Arc;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    error::BruteResponeError,
    model::{
        AttackVelocity, GetRollingStats, HeatmapCell, Individual, IpAbuse, IpSeen,
        ProcessedIndividual, ProtocolCombo, ProtocolComboRequest, RollingStats, TopCity,
        TopCountry, TopDaily, TopHourly, TopIp, TopLocation, TopOrg, TopPassword, TopPostal,
        TopProtocol, TopRegion, TopSubnet, TopTimezone, TopUsername, TopUsrPassCombo, TopWeekly,
        TopYearly,
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

pub struct RequestWithLimitAndOffset<T> {
    pub table: T, // just call ::default()
    pub limit: usize,
    pub max_limit: usize,
    pub offset: usize,
}

//////////////////////
// SYSTEM /w ACTOR //
////////////////////
#[derive(Clone)]
pub struct BruteSystem {
    /// PostgreSQL connection pool.
    pub db_pool: Pool<Postgres>,

    /// IP geolocation provider.
    pub geo: Arc<IpInfoProvider>,
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
    pub async fn new_brute(pg_pool: Pool<Postgres>, geo: IpInfoProvider) -> Self {
        Self {
            db_pool: pg_pool,
            geo: Arc::new(geo),
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
        let db_pool = self.db_pool.clone();
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
                    // Broadcast rolling stats asynchronously after each attack
                    tokio::spawn(async move {
                        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM individual")
                            .fetch_one(&db_pool)
                            .await
                            .unwrap_or(0);
                        let last_hour: i32 = sqlx::query_scalar(
                            "SELECT COALESCE(amount, 0) FROM top_hourly ORDER BY timestamp DESC LIMIT 1",
                        )
                        .fetch_optional(&db_pool)
                        .await
                        .unwrap_or(None)
                        .unwrap_or(0);
                        let top_protocol: Option<String> = sqlx::query_scalar(
                            "SELECT protocol FROM top_protocol ORDER BY amount DESC LIMIT 1",
                        )
                        .fetch_optional(&db_pool)
                        .await
                        .unwrap_or(None);
                        let top_country: Option<String> = sqlx::query_scalar(
                            "SELECT country FROM top_country ORDER BY amount DESC LIMIT 1",
                        )
                        .fetch_optional(&db_pool)
                        .await
                        .unwrap_or(None);
                        let stats = RollingStats {
                            total_attacks: total,
                            attacks_last_hour: last_hour,
                            top_protocol,
                            top_country,
                        };
                        crate::http::websocket::BruteServer::broadcast(
                            crate::http::websocket::ParseType::RollingStats,
                            stats,
                        );
                    });
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
                Err(e) => {
                    log::error!("processed_individual query failed: {:?}", e);
                    Err(BruteResponeError::InternalError(
                        "something definitely broke on our side".to_string(),
                    ))
                }
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

////////////////
// IP ABUSE   //
///////////////
impl Handler<RequestWithLimit<IpAbuse>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<IpAbuse>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimit<IpAbuse>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let fut = async move {
            let rows = sqlx::query_as::<_, IpAbuse>(
                "SELECT * FROM ip_abuse ORDER BY confidence_score DESC LIMIT $1;",
            )
            .bind(limit as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("query failed".to_string())),
            }
        };
        Box::pin(fut)
    }
}

/////////////////////
// ROLLING STATS  //
///////////////////
impl Handler<GetRollingStats> for BruteSystem {
    type Result = ResponseFuture<Result<RollingStats, BruteResponeError>>;

    fn handle(&mut self, _: GetRollingStats, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let fut = async move {
            let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM individual")
                .fetch_one(&db_pool)
                .await
                .unwrap_or(0);
            let last_hour: i32 = sqlx::query_scalar(
                "SELECT COALESCE(amount, 0) FROM top_hourly ORDER BY timestamp DESC LIMIT 1",
            )
            .fetch_optional(&db_pool)
            .await
            .unwrap_or(None)
            .unwrap_or(0);
            let top_protocol: Option<String> = sqlx::query_scalar(
                "SELECT protocol FROM top_protocol ORDER BY amount DESC LIMIT 1",
            )
            .fetch_optional(&db_pool)
            .await
            .unwrap_or(None);
            let top_country: Option<String> = sqlx::query_scalar(
                "SELECT country FROM top_country ORDER BY amount DESC LIMIT 1",
            )
            .fetch_optional(&db_pool)
            .await
            .unwrap_or(None);
            Ok(RollingStats {
                total_attacks: total,
                attacks_last_hour: last_hour,
                top_protocol,
                top_country,
            })
        };
        Box::pin(fut)
    }
}

//////////////////////
// ATTACK VELOCITY //
////////////////////
impl Handler<RequestWithLimit<AttackVelocity>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<AttackVelocity>, BruteResponeError>>;

    fn handle(
        &mut self,
        msg: RequestWithLimit<AttackVelocity>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let fut = async move {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;
            let since = now - 3_600_000;
            let rows = sqlx::query_as::<_, AttackVelocity>(
                r#"SELECT
                    (timestamp / 60000) * 60000 AS minute_bucket,
                    COUNT(*)::bigint AS amount
                FROM processed_individual
                WHERE timestamp > $1
                GROUP BY minute_bucket
                ORDER BY minute_bucket DESC
                LIMIT $2"#,
            )
            .bind(since)
            .bind(limit as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("something broke".to_string())),
            }
        };
        Box::pin(fut)
    }
}

////////////////
// IP SEEN    //
///////////////
impl Handler<RequestWithLimit<IpSeen>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<IpSeen>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimit<IpSeen>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let fut = async move {
            let rows = sqlx::query_as::<_, IpSeen>(
                "SELECT * FROM ip_seen ORDER BY total_sessions DESC LIMIT $1;",
            )
            .bind(limit as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("query failed".to_string())),
            }
        };
        Box::pin(fut)
    }
}

//////////////////////
// PROTOCOL COMBO  //
////////////////////
impl Handler<ProtocolComboRequest> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<ProtocolCombo>, BruteResponeError>>;

    fn handle(&mut self, msg: ProtocolComboRequest, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let fut = async move {
            let query = "SELECT username, password, COUNT(*)::bigint AS amount FROM individual WHERE protocol = $1 GROUP BY username, password ORDER BY amount DESC LIMIT $2;";
            let rows = sqlx::query_as::<_, ProtocolCombo>(query)
                .bind(&msg.protocol)
                .bind(msg.limit as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("query failed".to_string())),
            }
        };
        Box::pin(fut)
    }
}

////////////////
// TOP SUBNET //
///////////////
impl Handler<RequestWithLimit<TopSubnet>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopSubnet>, BruteResponeError>>;

    fn handle(
        &mut self,
        msg: RequestWithLimit<TopSubnet>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopSubnet>(
                r#"SELECT
                    regexp_replace(ip, '(\d+\.\d+\.\d+)\.\d+', '\1.0/24') AS subnet,
                    COUNT(*)::bigint AS amount
                FROM processed_individual
                WHERE ip ~ '^\d+\.\d+\.\d+\.\d+$'
                GROUP BY subnet
                ORDER BY amount DESC
                LIMIT $1"#,
            )
            .bind(limit as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("something broke".to_string())),
            }
        };
        Box::pin(fut)
    }
}

///////////////////
// HEATMAP CELL //
/////////////////
impl Handler<RequestWithLimit<HeatmapCell>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<HeatmapCell>, BruteResponeError>>;

    fn handle(
        &mut self,
        _msg: RequestWithLimit<HeatmapCell>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let fut = async move {
            let rows = sqlx::query_as::<_, HeatmapCell>(
                r#"SELECT
                    EXTRACT(DOW FROM to_timestamp(timestamp / 1000.0))::int AS day_of_week,
                    EXTRACT(HOUR FROM to_timestamp(timestamp / 1000.0))::int AS hour_of_day,
                    COUNT(*)::bigint AS amount
                FROM processed_individual
                GROUP BY day_of_week, hour_of_day
                ORDER BY day_of_week, hour_of_day"#,
            )
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("something broke".to_string())),
            }
        };
        Box::pin(fut)
    }
}

////////////////
// TOP DAILY //
//////////////
impl Handler<RequestWithLimit<TopDaily>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopDaily>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimit<TopDaily>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopDaily>(
                "SELECT * FROM top_daily ORDER BY timestamp DESC LIMIT $1;",
            )
            .bind(limit as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("something broke".to_string())),
            }
        };
        Box::pin(fut)
    }
}

/////////////////
// TOP WEEKLY //
///////////////
impl Handler<RequestWithLimit<TopWeekly>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopWeekly>, BruteResponeError>>;

    fn handle(
        &mut self,
        msg: RequestWithLimit<TopWeekly>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopWeekly>(
                "SELECT * FROM top_weekly ORDER BY timestamp DESC LIMIT $1;",
            )
            .bind(limit as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("something broke".to_string())),
            }
        };
        Box::pin(fut)
    }
}

/////////////////
// TOP YEARLY //
///////////////
impl Handler<RequestWithLimit<TopYearly>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopYearly>, BruteResponeError>>;

    fn handle(
        &mut self,
        msg: RequestWithLimit<TopYearly>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopYearly>(
                "SELECT * FROM top_yearly ORDER BY timestamp DESC LIMIT $1;",
            )
            .bind(limit as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("something broke".to_string())),
            }
        };
        Box::pin(fut)
    }
}

///////////////////////////////////////////////////
// HANDLER IMPLS FOR RequestWithLimitAndOffset  //
/////////////////////////////////////////////////

impl Handler<RequestWithLimitAndOffset<ProcessedIndividual>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<ProcessedIndividual>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<ProcessedIndividual>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let query = "SELECT * FROM processed_individual ORDER BY timestamp DESC LIMIT $1 OFFSET $2";
            let rows = sqlx::query_as::<_, ProcessedIndividual>(query)
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&db_pool)
                .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(e) => {
                    log::error!("processed_individual query failed: {:?}", e);
                    Err(BruteResponeError::InternalError("something definitely broke on our side".to_string()))
                }
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopUsername>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopUsername>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopUsername>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopUsername>(
                "SELECT * FROM top_username ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopPassword>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopPassword>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopPassword>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopPassword>(
                "SELECT * FROM top_password WHERE password !~ '^X{2,}$' ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopIp>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopIp>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopIp>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopIp>(
                "SELECT * FROM top_ip ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopProtocol>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopProtocol>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopProtocol>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopProtocol>(
                "SELECT * FROM top_protocol ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopCountry>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopCountry>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopCountry>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopCountry>(
                "SELECT * FROM top_country ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("a country broke the server.".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopCity>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopCity>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopCity>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopCity>(
                "SELECT * FROM top_city ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopRegion>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopRegion>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopRegion>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopRegion>(
                "SELECT * FROM top_region ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopTimezone>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopTimezone>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopTimezone>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopTimezone>(
                "SELECT * FROM top_timezone ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopOrg>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopOrg>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopOrg>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopOrg>(
                "SELECT * FROM top_org ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopPostal>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopPostal>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopPostal>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopPostal>(
                "SELECT * FROM top_postal WHERE postal !~ '^\\s*$' ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopLocation>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopLocation>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopLocation>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopLocation>(
                "SELECT * FROM top_loc ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopUsrPassCombo>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopUsrPassCombo>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopUsrPassCombo>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopUsrPassCombo>(
                "SELECT * FROM top_usr_pass_combo WHERE password !~ '^X{2,}$' ORDER BY amount DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopHourly>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopHourly>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopHourly>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopHourly>(
                "SELECT * FROM top_hourly ORDER BY timestamp DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something definitely broke on our side".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopDaily>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopDaily>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopDaily>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopDaily>(
                "SELECT * FROM top_daily ORDER BY timestamp DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something broke".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopWeekly>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopWeekly>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopWeekly>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopWeekly>(
                "SELECT * FROM top_weekly ORDER BY timestamp DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something broke".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopYearly>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopYearly>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopYearly>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopYearly>(
                "SELECT * FROM top_yearly ORDER BY timestamp DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(rows) => Ok(rows),
                Err(_) => Err(BruteResponeError::InternalError("something broke".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<TopSubnet>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<TopSubnet>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<TopSubnet>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, TopSubnet>(
                r#"SELECT
                    regexp_replace(ip, '(\d+\.\d+\.\d+)\.\d+', '\1.0/24') AS subnet,
                    COUNT(*)::bigint AS amount
                FROM processed_individual
                WHERE ip ~ '^\d+\.\d+\.\d+\.\d+$'
                GROUP BY subnet
                ORDER BY amount DESC
                LIMIT $1 OFFSET $2"#,
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("something broke".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<IpSeen>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<IpSeen>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<IpSeen>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, IpSeen>(
                "SELECT * FROM ip_seen ORDER BY total_sessions DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("query failed".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<IpAbuse>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<IpAbuse>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<IpAbuse>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let rows = sqlx::query_as::<_, IpAbuse>(
                "SELECT * FROM ip_abuse ORDER BY confidence_score DESC LIMIT $1 OFFSET $2;",
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("query failed".to_string())),
            }
        };
        Box::pin(fut)
    }
}

impl Handler<RequestWithLimitAndOffset<AttackVelocity>> for BruteSystem {
    type Result = ResponseFuture<Result<Vec<AttackVelocity>, BruteResponeError>>;

    fn handle(&mut self, msg: RequestWithLimitAndOffset<AttackVelocity>, _: &mut Self::Context) -> Self::Result {
        let db_pool = self.db_pool.clone();
        let limit = msg.limit;
        let offset = msg.offset;
        let fut = async move {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;
            let since = now - 3_600_000;
            let rows = sqlx::query_as::<_, AttackVelocity>(
                r#"SELECT
                    (timestamp / 60000) * 60000 AS minute_bucket,
                    COUNT(*)::bigint AS amount
                FROM processed_individual
                WHERE timestamp > $1
                GROUP BY minute_bucket
                ORDER BY minute_bucket DESC
                LIMIT $2 OFFSET $3"#,
            )
            .bind(since)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db_pool)
            .await;
            match rows {
                Ok(r) => Ok(r),
                Err(_) => Err(BruteResponeError::InternalError("something broke".to_string())),
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
        Individual, IpSeen, ProcessedIndividual, TopCity, TopCountry, TopDaily, TopHourly, TopIp,
        TopLocation, TopOrg, TopPassword, TopPostal, TopProtocol, TopRegion, TopTimezone,
        TopUsername, TopUsrPassCombo, TopWeekly, TopYearly,
    };
    use brute_core::traits::geo::GeoProvider;
    use log::info;
    use sha1::{Digest, Sha1};
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

    #[derive(serde::Deserialize)]
    struct AbuseIpDbResponse {
        data: AbuseIpDbData,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AbuseIpDbData {
        abuse_confidence_score: i32,
        total_reports: i32,
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
            IpSeen::report(self, &individual).await?;
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

            // AbuseIPDB check — fire and forget
            if let Ok(api_key) = std::env::var("ABUSEIPDB_KEY") {
                let ip = individual.ip().to_string();
                let pool = self.brute.db_pool.clone();
                tokio::spawn(async move {
                    // skip if recently checked (< 24h)
                    let existing: Option<i64> = sqlx::query_scalar(
                        "SELECT checked_at FROM ip_abuse WHERE ip = $1",
                    )
                    .bind(&ip)
                    .fetch_optional(&pool)
                    .await
                    .unwrap_or_else(|e| {
                        log::error!("AbuseIPDB: failed to query existing record for {}: {}", ip, e);
                        None
                    });

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as i64;
                    if let Some(t) = existing {
                        if now - t < 86_400_000 {
                            return;
                        }
                    }

                    let url = format!(
                        "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
                        ip
                    );
                    let client = reqwest::Client::new();
                    match client
                        .get(&url)
                        .header("Key", &api_key)
                        .header("Accept", "application/json")
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            match resp.json::<AbuseIpDbResponse>().await {
                                Ok(data) => {
                                    sqlx::query(
                                        r#"
                                        INSERT INTO ip_abuse (ip, confidence_score, total_reports, checked_at)
                                        VALUES ($1, $2, $3, $4)
                                        ON CONFLICT (ip) DO UPDATE SET
                                            confidence_score = EXCLUDED.confidence_score,
                                            total_reports = EXCLUDED.total_reports,
                                            checked_at = EXCLUDED.checked_at
                                    "#,
                                    )
                                    .bind(&ip)
                                    .bind(data.data.abuse_confidence_score)
                                    .bind(data.data.total_reports)
                                    .bind(now)
                                    .execute(&pool)
                                    .await
                                    .unwrap_or_else(|e| {
                                        log::error!("AbuseIPDB: failed to upsert abuse record for {}: {}", ip, e);
                                        Default::default()
                                    });
                                }
                                Err(e) => {
                                    log::error!("AbuseIPDB: failed to parse response for {}: {}", ip, e);
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("AbuseIPDB: HTTP request failed for {}: {}", ip, e);
                        }
                    }
                });
            }

            // HIBP check — fire and forget
            {
                let password = individual.password().to_string();
                let pool = self.brute.db_pool.clone();
                tokio::spawn(async move {
                    // Compute SHA1 of the password
                    let mut hasher = Sha1::new();
                    hasher.update(password.as_bytes());
                    let hash_bytes = hasher.finalize();
                    let hex = format!("{:X}", hash_bytes);
                    let (prefix, suffix) = (&hex[..5], &hex[5..]);

                    let client = reqwest::Client::new();
                    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
                    match client
                        .get(&url)
                        .header("Add-Padding", "true")
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            match resp.text().await {
                                Ok(body) => {
                                    let breached = body.lines().any(|line| {
                                        line.split(':')
                                            .next()
                                            .map(|h| h.eq_ignore_ascii_case(suffix))
                                            .unwrap_or(false)
                                    });
                                    if breached {
                                        sqlx::query(
                                            "UPDATE top_password SET is_breached = TRUE WHERE password = $1",
                                        )
                                        .bind(&password)
                                        .execute(&pool)
                                        .await
                                        .unwrap_or_else(|e| {
                                            log::error!("HIBP: failed to mark password as breached: {}", e);
                                            Default::default()
                                        });
                                    }
                                }
                                Err(e) => {
                                    log::error!("HIBP: failed to read response body: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("HIBP: HTTP request failed for password hash prefix {}: {}", prefix, e);
                        }
                    }
                });
            }

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
            let geo = &reporter.brute.geo;
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

            let ip_exists = sqlx::query_as::<_, ProcessedIndividual>(select_query)
                .bind(model.ip())
                .fetch_optional(pool)
                .await?;

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
                    info!("Fetching new details from IPinfo for IP: {}", model.ip());
                    let g = match geo.lookup(model.ip()).await {
                        Ok(d) => d,
                        Err(e) => {
                            log::error!("IPinfo lookup failed for {}: {:?}", model.ip(), e);
                            return Err(anyhow::anyhow!("IPinfo lookup failed: {}", e));
                        }
                    };

                    sqlx::query_as::<_, ProcessedIndividual>(insert_query)
                        .bind(model.id())
                        .bind(model.username())
                        .bind(model.password())
                        .bind(model.ip())
                        .bind(model.protocol())
                        .bind(&g.hostname)
                        .bind(&g.city)
                        .bind(&g.region)
                        .bind(&g.country)
                        .bind(&g.loc)
                        .bind(&g.org)
                        .bind(g.postal.as_deref().or(Some("")))
                        .bind(&g.asn)
                        .bind(&g.asn_name)
                        .bind(&g.asn_domain)
                        .bind(&g.asn_route)
                        .bind(&g.asn_type)
                        .bind(&g.company_name)
                        .bind(&g.company_domain)
                        .bind(&g.company_type)
                        .bind(g.vpn.unwrap_or(false))
                        .bind(g.proxy.unwrap_or(false))
                        .bind(g.tor.unwrap_or(false))
                        .bind(g.relay.unwrap_or(false))
                        .bind(g.hosting.unwrap_or(false))
                        .bind(g.service.as_deref().unwrap_or(""))
                        .bind(&g.abuse_address)
                        .bind(&g.abuse_country)
                        .bind(&g.abuse_email)
                        .bind(&g.abuse_name)
                        .bind(&g.abuse_network)
                        .bind(&g.abuse_phone)
                        .bind(&g.domain_ip)
                        .bind(g.domain_total.unwrap_or(0))
                        .bind(&g.domains)
                        .bind(model.timestamp)
                        .bind(&g.timezone)
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

    impl Reportable<BruteReporter<BruteSystem>, Individual> for IpSeen {
        async fn report(
            reporter: &BruteReporter<BruteSystem>,
            model: &Individual,
        ) -> anyhow::Result<Self> {
            let pool = &reporter.brute.db_pool;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
            let result = sqlx::query_as::<_, IpSeen>(
                r#"
                INSERT INTO ip_seen (ip, first_seen, last_seen, total_sessions)
                VALUES ($1, $2, $2, 1)
                ON CONFLICT (ip) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    total_sessions = ip_seen.total_sessions + 1
                RETURNING *;
            "#,
            )
            .bind(model.ip())
            .bind(now)
            .fetch_one(pool)
            .await?;
            Ok(result)
        }
    }
}
