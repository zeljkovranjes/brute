use worker::Env;

pub async fn run(env: &Env) -> worker::Result<()> {
    let db = env.d1("DB")?;
    let retention_days: i64 = env
        .var("DATA_RETENTION_DAYS")
        .map(|v| v.to_string().parse().unwrap_or(90))
        .unwrap_or(90);

    // D1 stores timestamps in Unix milliseconds — calculate cutoff in ms.
    let cutoff_ms = (js_sys::Date::now() as i64) - (retention_days * 86_400_000);

    for table in &["individual", "processed_individual"] {
        db.prepare(&format!("DELETE FROM {} WHERE timestamp < ?1", table))
            .bind(&[cutoff_ms.into()])?
            .run()
            .await?;
    }
    Ok(())
}
