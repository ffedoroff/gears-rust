// Created: 2026-04-16 by Constructor Tech
//! Database migrations for the resource-group gear.

use sea_orm_migration::MigratorTrait;

mod m20260306_000001_initial;

pub struct Migrator;

impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn sea_orm_migration::MigrationTrait>> {
        vec![Box::new(m20260306_000001_initial::Migration)]
    }
}
