use sqlx::SqlitePool;

pub async fn save_token(token_type: String, uuid: String, user_id: i64, pool: &SqlitePool) -> Result<String, String> {
    sqlx::query("INSERT INTO tokens(type, uuid, user_id, date_created) VALUES($1, $2, $3, datetime('now'));")
    .bind(&token_type)
    .bind(&uuid)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|err| {
        dbg!(err);
        "Internal Error".to_owned()
    })?;
    
    Ok("OK".to_string())
}

pub async fn delete_token(token_type: String, uuid: String, pool: &SqlitePool) -> Result<String, String> {
    sqlx::query("DELETE FROM tokens WHERE uuid=$1 AND type=$2;")
    .bind(&token_type)
    .bind(&uuid)
    .execute(pool)
    .await
    .map_err(|err| {
        dbg!(err);
        "Internal Error".to_owned()
    })?;
    
    Ok("OK".to_string())
}
