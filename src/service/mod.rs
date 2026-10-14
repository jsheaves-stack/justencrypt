//! Everything a client can do, end to end, independent of how its requests
//! arrive. The web layer calls these functions and turns their results into
//! responses; nothing here knows about HTTP.

pub mod accounts;
pub mod admin;
pub mod auth;
pub mod chunks;
pub mod credentials;
pub mod files;
pub mod folders;
pub mod limits;
pub mod thumbnails;
pub mod uploads;
