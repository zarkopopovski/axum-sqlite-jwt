use axum::{
    routing::{get, post},
    extract::DefaultBodyLimit,
    Router,
};

use std::net::SocketAddr;

use tower_http::{
    cors::{Any, CorsLayer},
};

use once_cell::sync::Lazy;

use sqlx::{migrate::MigrateDatabase, Sqlite, SqlitePool};

mod controllers;
mod models;
mod services;

const DB_URL: &str = "sqlite://template.db";

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool
}

static KEYS: Lazy<controllers::user::Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "Your secret here".to_owned());
    controllers::user::Keys::new(secret.as_bytes())
});

#[tokio::main]
async fn main() {
    if !Sqlite::database_exists(DB_URL).await.unwrap_or(false) {
        println!("Creating database {}", DB_URL);
        match Sqlite::create_database(DB_URL).await {
            Ok(_) => println!("Create db success"),
            Err(error) => panic!("error: {}", error),
        }
    } else {
        println!("Database already exists");
    }
    
    let cors = CorsLayer::new().allow_origin(Any);

    let db = SqlitePool::connect(DB_URL).await.unwrap();
    
    let app_state = AppState {
        pool: db,
    };
    
    let result = sqlx::query("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY NOT NULL, username VARCHAR(80) NOT NULL, password VARCHAR(60) NOT NULL);")
    .execute(&app_state.pool)
    .await
    .unwrap();
    
    println!("Create user table result: {:?}", result);
    
    let result2 = sqlx::query("CREATE TABLE IF NOT EXISTS tokens (type VARCHAR, uuid TEXT, user_id INTEGER, date_created VARCHAR);")
    .execute(&app_state.pool)
    .await
    .unwrap();
    
    println!("Create tokens table result: {:?}", result2);

    let app = Router::new()
        .route("/", get(root))
        .route("/register", post(controllers::user::create_user))
        .route("/login", post(controllers::user::login_user))
        .route("/logout", get(controllers::user::logout_user))
        .route("/refresh/:refresh_token", get(controllers::user::refresh_token))
        .layer(cors)
        .layer(DefaultBodyLimit::disable())
        .with_state(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn root() -> &'static str {
    "Hello, World!"
}

/// Tokio signal handler that will wait for a user to press CTRL+C.
/// We use this in our hyper `Server` method `with_graceful_shutdown`.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Expect shutdown signal handler");
    println!("signal shutdown");
}
