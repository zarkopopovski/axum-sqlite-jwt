use axum::{
    http::StatusCode,
    extract::{Multipart, Path, State, TypedHeader},
    headers::{
        authorization::Bearer,
        Authorization,
    },

    Json,
};

use std::{
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use jsonwebtoken::{encode, decode, Header, Validation};
use jsonwebtoken::{DecodingKey, EncodingKey};
//use serde_json;
//use sha3::Digest;

use uuid::Uuid;

use crate::{ models, AppState, KEYS };

use sqlx::SqlitePool;

#[derive(Deserialize)]
pub struct CreateUser {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct User {
    id: i64,
    username: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Claims {
    pub id: i64,
    pub email: String,
    pub uuid: String,
    pub exp: u64,
}

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

pub async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUser>,
) -> Result<(axum::http::StatusCode, axum::Json<User>), String> {
    // insert your application logic here
    if payload.username.is_empty() || payload.password.is_empty() {
        return Err("Error, missing data!!!".to_string());
    }
    
    // let hashed_password = sha3::Sha3_256::digest(payload.password.as_bytes());
    // let password = format!("{:x}", hashed_password);
    
    let user = User {
        id: 1337,
        username: payload.username.clone(),
        access_token: None,
        refresh_token: None,
    };
    
    sqlx::query("INSERT INTO users(username, password) VALUES($1, $2)")
    .bind(&payload.username)
    .bind(&payload.password)
    .execute(&state.pool)
    .await
    .map_err(|err| {
        dbg!(err);
        "Internal Error".to_owned()
    })?;

   Ok((StatusCode::CREATED, Json(user)))
}

pub async fn login_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUser>,
) -> Result<(axum::http::StatusCode, axum::Json<User>), String> {
    
    let mut user = User {
        id: 1337,
        username: payload.username.clone(),
        access_token: None,
        refresh_token: None
    };
    
    let uuid_v4 = Uuid::new_v4();
    
    let uuid_v4_str = format!("{}", uuid_v4);
    let access_token = create_token(&user, payload.username.clone(), uuid_v4_str, false, &state.pool).await;
    
    let uuid_v4_refresh = format!("{}++{}", uuid_v4, user.id);
    let refresh_token = create_token(&user, payload.username.clone(), uuid_v4_refresh, true, &state.pool).await;
    
    user.access_token = Some(access_token);
    user.refresh_token = Some(refresh_token);
    
    Ok((StatusCode::CREATED, Json(user)))
}

pub async fn logout_user(
    State(state): State<AppState>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<(axum::http::StatusCode, axum::Json<String>), String> {
    let data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
        .map_err(|_| "Invalid Token".to_string())?;
    
    let uuid_v4_refresh = format!("{}++{}", &data.claims.uuid, data.claims.id);
    
    models::token::delete_token("ACCESS".to_string(), data.claims.uuid, &state.pool).await.expect("Error");
    models::token::delete_token("REFRESH".to_string(), uuid_v4_refresh, &state.pool).await.expect("Error");
    
    Ok((StatusCode::CREATED, Json("Success".to_string())))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Path(refresh_token): Path<String>,
) -> Result<(axum::http::StatusCode, axum::Json<Tokens>), String> {
    let data = decode::<Claims>(refresh_token.as_str(), &KEYS.decoding, &Validation::default())
        .map_err(|_| "Invalid Token".to_string())?;
    
    let refresh_uuid = data.claims.uuid;
    let user_id = data.claims.id;
    
    models::token::delete_token("REFRESH".to_string(), refresh_uuid, &state.pool).await.expect("Error");

    let user = User {
        id: user_id,
        username: "email@tt.com".to_string(),
        access_token: None,
        refresh_token: None
    };
    
    let uuid_v4 = Uuid::new_v4();
    
    let uuid_v4_str = format!("{}", uuid_v4);
    let access_token = create_token(&user, user.username.clone(), uuid_v4_str, false, &state.pool).await;
    
    let uuid_v4_refresh = format!("{}++{}", uuid_v4, user.id);
    let refresh_token = create_token(&user, user.username.clone(), uuid_v4_refresh, true, &state.pool).await;
    
    let tokens = Tokens{
        access_token: access_token,
        refresh_token: refresh_token
    };
    
    Ok((StatusCode::CREATED, axum::Json(tokens)))
}

pub async fn create_token(user: &User, username: String, uuid_v4: String, is_refresh: bool, pool: &SqlitePool) -> String {
    let mut t_time: u64 = 7200;
    
    if is_refresh {
        t_time = 9600;
    }
     
    let claims = Claims {
        id: user.id,
        email: username,
        uuid: uuid_v4.clone(),
        exp: (SystemTime::now() + Duration::from_secs(t_time))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let token = match encode(&Header::default(), &claims, &KEYS.encoding)
        .map_err(|_| "Error token creation".to_string()) {
            Ok(token_str) => token_str,
            Err(_) => panic!("Error"),
        };
    
    if is_refresh {
        models::token::save_token("REFRESH".to_string(), uuid_v4, user.id, pool).await.expect("Error");
    } else {
        models::token::save_token("ACCESS".to_string(), uuid_v4, user.id, pool).await.expect("Error");
    }
    
    token
}
