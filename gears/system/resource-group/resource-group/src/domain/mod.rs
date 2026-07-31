// Created: 2026-04-16 by Constructor Tech
#![allow(unknown_lints)]
#![allow(de0301_no_infra_in_domain)]

pub mod error;
pub mod group_service;
pub(crate) mod hierarchy_filter;
pub mod local_client;
pub mod membership_service;
pub mod read_service;
pub mod repo;
pub mod seeding;
pub mod type_service;
pub mod validation;

/// Type alias for the database provider used by domain services.
pub(crate) type DbProvider = toolkit_db::DBProvider<toolkit_db::DbError>;
