#![recursion_limit = "256"]
#![deny(unsafe_code)]

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

#[macro_use]
pub mod diagnostics;

#[macro_use]
pub mod error;

pub mod config;
pub mod data;
pub mod server;
