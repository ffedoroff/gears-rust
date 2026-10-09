// Created: 2026-07-27 by Constructor Tech
// Copied verbatim (module doc's gear name aside) from gears/system/resource-group/resource-
// group/tests/common/query_recorder.rs for the file-storage DB-behavior audit.
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
//! SQL query recorder for DB-behavior audits (SQLite only).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Duration;

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QueryKind {
    Select,
    Insert,
    Update,
    Delete,
    Other,
}

impl QueryKind {
    fn from_sql(sql: &str) -> Self {
        match sql
            .split_whitespace()
            .next()
            .map(str::to_ascii_uppercase)
            .as_deref()
        {
            Some("SELECT") => Self::Select,
            Some("INSERT") => Self::Insert,
            Some("UPDATE") => Self::Update,
            Some("DELETE") => Self::Delete,
            _ => Self::Other,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Other => "OTHER",
        }
    }
}

impl std::fmt::Display for QueryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct RecordedQuery {
    /// Monotonic sequence number, in execution order.
    pub seq: usize,
    pub kind: QueryKind,
    pub table: Option<String>,
    pub sql: String,
    /// Human-readable SQL with bound values injected back in (via `SeaORM`'s own `Statement`
    /// `Display` impl) -- for trace dumps, not for matching.
    pub raw_sql: String,
    pub in_tx: bool,
    pub param_count: usize,
    pub elapsed: Duration,
    pub failed: bool,
}

static RE_STRING_LIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"'(?:[^']|'')*'").expect("valid regex"));
static RE_NUMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d+\b").expect("valid regex"));
static RE_WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").expect("valid regex"));
static RE_PG_IN_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bIN\s*\(\s*\$\d+(?:\s*,\s*\$\d+)*\s*\)").expect("valid regex")
});
static RE_QM_IN_LIST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bIN\s*\(\s*\?(?:\s*,\s*\?)*\s*\)").expect("valid regex"));

static RE_INSERT_TABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^insert\s+into\s+"?([a-zA-Z_][a-zA-Z0-9_]*)"?"#).expect("valid regex")
});
static RE_UPDATE_TABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^update\s+"?([a-zA-Z_][a-zA-Z0-9_]*)"?"#).expect("valid regex")
});
static RE_DELETE_TABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^delete\s+from\s+"?([a-zA-Z_][a-zA-Z0-9_]*)"?"#).expect("valid regex")
});
static RE_FROM_TABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bfrom\s+"?([a-zA-Z_][a-zA-Z0-9_]*)"?"#).expect("valid regex")
});

#[must_use]
pub fn normalize_sql(sql: &str) -> String {
    let s = RE_STRING_LIT.replace_all(sql, "'?'");
    let s = RE_PG_IN_LIST.replace_all(&s, "IN ($$N)");
    let s = RE_QM_IN_LIST.replace_all(&s, "IN (?)");
    let s = RE_NUMBER.replace_all(&s, "?");
    let s = RE_WHITESPACE.replace_all(&s, " ");
    s.trim().to_owned()
}

fn extract_table(kind: QueryKind, raw_sql: &str) -> Option<String> {
    let re = match kind {
        QueryKind::Insert => &*RE_INSERT_TABLE,
        QueryKind::Update => &*RE_UPDATE_TABLE,
        QueryKind::Delete => &*RE_DELETE_TABLE,
        QueryKind::Select => &*RE_FROM_TABLE,
        QueryKind::Other => return None,
    };
    re.captures(raw_sql).map(|c| c[1].to_owned())
}

/// Shared handle to a captured SQL trace.
#[derive(Clone)]
pub struct QueryRecorder {
    events: Arc<Mutex<Vec<RecordedQuery>>>,
}

impl QueryRecorder {
    #[cfg(test)]
    fn from_events_for_testing(events: Vec<RecordedQuery>) -> Self {
        Self {
            events: Arc::new(Mutex::new(events)),
        }
    }

    /// Build a fresh recorder and the `SeaORM` metric callback that feeds it.
    #[must_use = "the recorder observes nothing unless its callback is passed to \
                  connect_db_with_metric_callback before the connection is wrapped"]
    pub fn attach() -> (
        Self,
        impl Fn(&sea_orm::metric::Info<'_>) + Send + Sync + 'static,
    ) {
        let events: Arc<Mutex<Vec<RecordedQuery>>> = Arc::new(Mutex::new(Vec::new()));
        let seq = Arc::new(AtomicUsize::new(0));
        let recorder = Self {
            events: Arc::clone(&events),
        };

        let callback = move |info: &sea_orm::metric::Info<'_>| {
            let raw_sql = info.statement.sql.clone();
            let kind = QueryKind::from_sql(&raw_sql);
            let table = extract_table(kind, &raw_sql);
            let sql = normalize_sql(&raw_sql);
            // Precise, not a heuristic -- see module docs.
            let in_tx = toolkit_db::secure::in_transaction_for_testing();
            let param_count = info
                .statement
                .values
                .as_ref()
                .map_or(0, |values| values.0.len());
            let n = seq.fetch_add(1, Ordering::Relaxed);
            let rec = RecordedQuery {
                seq: n,
                kind,
                table,
                sql,
                raw_sql: info.statement.to_string(),
                in_tx,
                param_count,
                elapsed: info.elapsed,
                failed: info.failed,
            };
            events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(rec);
        };

        (recorder, callback)
    }

    /// All captured statements, in execution order.
    #[must_use]
    pub fn events(&self) -> Vec<RecordedQuery> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn total(&self) -> usize {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    #[must_use]
    pub fn total_params(&self) -> usize {
        self.events().iter().map(|e| e.param_count).sum()
    }

    #[must_use]
    pub fn total_elapsed(&self) -> std::time::Duration {
        self.events().iter().map(|e| e.elapsed).sum()
    }

    #[must_use]
    pub fn failed_statements(&self) -> Vec<RecordedQuery> {
        self.events().into_iter().filter(|e| e.failed).collect()
    }

    /// Clear the recorded trace.
    pub fn clear(&self) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    #[must_use]
    pub fn stats(&self) -> BTreeMap<(QueryKind, String), usize> {
        let mut out: BTreeMap<(QueryKind, String), usize> = BTreeMap::new();
        for e in self.events() {
            let table = e.table.unwrap_or_else(|| "<none>".to_owned());
            *out.entry((e.kind, table)).or_insert(0) += 1;
        }
        out
    }

    #[must_use]
    pub fn writes_outside_tx(&self) -> Vec<RecordedQuery> {
        self.events()
            .into_iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    QueryKind::Insert | QueryKind::Update | QueryKind::Delete
                )
            })
            .filter(|e| !e.in_tx)
            .collect()
    }

    #[must_use]
    pub fn redundant_reads_after_write(&self) -> Vec<(RecordedQuery, RecordedQuery)> {
        let events = self.events();
        let mut out = Vec::new();
        for w in events
            .iter()
            .filter(|e| matches!(e.kind, QueryKind::Insert | QueryKind::Update))
        {
            let Some(table) = w.table.as_deref() else {
                continue;
            };
            let next_same_table = events
                .iter()
                .find(|e| e.seq > w.seq && e.table.as_deref() == Some(table));
            if let Some(next) = next_same_table
                && next.kind == QueryKind::Select
            {
                out.push((w.clone(), next.clone()));
            }
        }
        out
    }

    #[must_use]
    pub fn dump(&self) -> String {
        let mut out = String::new();
        let mut last_in_tx = false;
        for (i, e) in self.events().into_iter().enumerate() {
            if i == 0 || e.in_tx != last_in_tx {
                let marker = if e.in_tx {
                    "-- [enter tx scope] --"
                } else {
                    "-- [outside tx] --"
                };
                writeln!(out, "{marker}").expect("String Write is infallible");
            }
            last_in_tx = e.in_tx;
            let text = if e.failed { &e.raw_sql } else { &e.sql };
            let elapsed = format!("{:.1?}", e.elapsed);
            writeln!(
                out,
                "{:>3}  {:<7} {:<32} in_tx={:<5} params={:<3} {}{:>7}  {text}",
                e.seq,
                e.kind,
                e.table.as_deref().unwrap_or("-"),
                e.in_tx,
                e.param_count,
                if e.failed { "[FAILED] " } else { "" },
                elapsed,
            )
            .expect("String Write is infallible");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{QueryKind, extract_table};

    #[test]
    fn kind_from_sql_classifies_by_leading_keyword() {
        let cases: Vec<(&str, QueryKind)> = vec![
            ("SELECT * FROM foo", QueryKind::Select),
            ("  select id from foo", QueryKind::Select),
            ("INSERT INTO foo (a) VALUES (?)", QueryKind::Insert),
            ("UPDATE foo SET a = ?", QueryKind::Update),
            ("DELETE FROM foo WHERE id = ?", QueryKind::Delete),
            ("PRAGMA foreign_keys = ON", QueryKind::Other),
            ("CREATE TABLE foo (id INTEGER)", QueryKind::Other),
            ("BEGIN", QueryKind::Other),
        ];
        for (sql, expected) in cases {
            assert_eq!(QueryKind::from_sql(sql), expected, "sql: {sql}");
        }
    }

    #[test]
    fn extract_table_finds_target_per_kind() {
        let cases: Vec<(QueryKind, &str, Option<&str>)> = vec![
            (
                QueryKind::Insert,
                r#"INSERT INTO "resource_group" ("id") VALUES (?)"#,
                Some("resource_group"),
            ),
            (
                QueryKind::Update,
                r#"UPDATE "gts_type" SET "name" = ? WHERE "id" = ?"#,
                Some("gts_type"),
            ),
            (
                QueryKind::Delete,
                r#"DELETE FROM "resource_group_closure" WHERE "descendant_id" = ?"#,
                Some("resource_group_closure"),
            ),
            (
                QueryKind::Select,
                r#"SELECT "id" FROM "resource_group" WHERE "id" = ?"#,
                Some("resource_group"),
            ),
            (QueryKind::Other, "PRAGMA foreign_keys = ON", None),
        ];
        for (kind, sql, expected) in cases {
            let actual = extract_table(kind, sql);
            assert_eq!(actual.as_deref(), expected, "sql: {sql}");
        }
    }

    #[test]
    fn normalize_sql_table_driven_cases() {
        let cases: Vec<(&str, &str)> = vec![
            (
                "SELECT  *   FROM foo\nWHERE id = 42",
                "SELECT * FROM foo WHERE id = ?",
            ),
            (
                "SELECT * FROM foo WHERE name = 'literal value, with comma'",
                "SELECT * FROM foo WHERE name = '?'",
            ),
            (
                r#"SELECT * FROM "gts_type" WHERE "id" IN (?, ?, ?)"#,
                r#"SELECT * FROM "gts_type" WHERE "id" IN (?)"#,
            ),
            (
                r#"SELECT * FROM "t" WHERE "id" IN (?, ?)"#,
                r#"SELECT * FROM "t" WHERE "id" IN (?)"#,
            ),
            (
                r#"SELECT * FROM "t" WHERE "id" IN ($1, $2)"#,
                r#"SELECT * FROM "t" WHERE "id" IN ($N)"#,
            ),
            (
                r#"SELECT * FROM "t" WHERE "id" IN ($1, $2, $3)"#,
                r#"SELECT * FROM "t" WHERE "id" IN ($N)"#,
            ),
            (
                "INSERT INTO t (a, b) VALUES (?, ?)",
                "INSERT INTO t (a, b) VALUES (?, ?)",
            ),
            (
                "INSERT INTO t (a, b, c) VALUES (?, ?, ?)",
                "INSERT INTO t (a, b, c) VALUES (?, ?, ?)",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(super::normalize_sql(input), expected, "input: {input}");
        }
    }

    #[test]
    fn normalize_sql_placeholder_list_length_does_not_change_shape() {
        let three = super::normalize_sql(r#"SELECT * FROM "gts_type" WHERE "id" IN (?, ?, ?)"#);
        let thirty = super::normalize_sql(&format!(
            r#"SELECT * FROM "gts_type" WHERE "id" IN ({})"#,
            vec!["?"; 30].join(", ")
        ));
        assert_eq!(
            three, thirty,
            "IN-list length must not change the normalized shape (scale-invariance grouping)"
        );
    }

    fn make(seq: usize, kind: QueryKind, table: Option<&str>, in_tx: bool) -> super::RecordedQuery {
        super::RecordedQuery {
            seq,
            kind,
            table: table.map(str::to_owned),
            sql: format!("<stmt {seq}>"),
            raw_sql: format!("<stmt {seq}>"),
            in_tx,
            param_count: 0,
            elapsed: std::time::Duration::ZERO,
            failed: false,
        }
    }

    fn make_failed(
        seq: usize,
        kind: QueryKind,
        table: Option<&str>,
        in_tx: bool,
    ) -> super::RecordedQuery {
        super::RecordedQuery {
            failed: true,
            ..make(seq, kind, table, in_tx)
        }
    }

    #[test]
    fn total_params_sums_param_count_across_events() {
        let mut a = make(0, QueryKind::Select, Some("gts_type"), false);
        a.param_count = 3;
        let mut b = make(1, QueryKind::Insert, Some("resource_group"), true);
        b.param_count = 5;
        let rec = super::QueryRecorder::from_events_for_testing(vec![a, b]);
        assert_eq!(rec.total_params(), 8);
    }

    #[test]
    fn stats_groups_by_kind_and_table() {
        let rec = super::QueryRecorder::from_events_for_testing(vec![
            make(0, QueryKind::Select, Some("gts_type"), false),
            make(1, QueryKind::Select, Some("gts_type"), false),
            make(2, QueryKind::Insert, Some("resource_group"), true),
            make(3, QueryKind::Other, None, false),
        ]);
        let stats = rec.stats();
        assert_eq!(
            stats.get(&(QueryKind::Select, "gts_type".to_owned())),
            Some(&2)
        );
        assert_eq!(
            stats.get(&(QueryKind::Insert, "resource_group".to_owned())),
            Some(&1)
        );
        assert_eq!(
            stats.get(&(QueryKind::Other, "<none>".to_owned())),
            Some(&1)
        );
        assert_eq!(rec.total(), 4);
    }

    #[test]
    fn writes_outside_tx_flags_only_untransacted_writes() {
        let rec = super::QueryRecorder::from_events_for_testing(vec![
            make(0, QueryKind::Select, Some("gts_type"), false), // read, ignored regardless of in_tx
            make(
                1,
                QueryKind::Insert,
                Some("resource_group_membership"),
                false,
            ), // flagged
            make(2, QueryKind::Insert, Some("resource_group"), true), // in tx, clean
            make(3, QueryKind::Delete, Some("resource_group"), false), // flagged
        ]);
        let flagged = rec.writes_outside_tx();
        assert_eq!(
            flagged.len(),
            2,
            "expected exactly the two untransacted writes"
        );
        assert!(flagged.iter().all(|e| !e.in_tx));
        assert_eq!(flagged[0].seq, 1);
        assert_eq!(flagged[1].seq, 3);
    }

    #[test]
    fn writes_outside_tx_empty_when_all_writes_are_transacted() {
        let rec = super::QueryRecorder::from_events_for_testing(vec![
            make(0, QueryKind::Select, Some("gts_type"), false),
            make(1, QueryKind::Insert, Some("gts_type"), true),
            make(2, QueryKind::Update, Some("gts_type"), true),
        ]);
        assert!(rec.writes_outside_tx().is_empty());
    }

    #[test]
    fn redundant_reads_after_write_flags_reread_of_same_table() {
        let rec = super::QueryRecorder::from_events_for_testing(vec![
            make(0, QueryKind::Insert, Some("resource_group"), true),
            make(1, QueryKind::Select, Some("resource_group"), true), // redundant re-read
            make(2, QueryKind::Insert, Some("resource_group_closure"), true),
            make(3, QueryKind::Insert, Some("resource_group_closure"), true), // another write first, not a read
        ]);
        let hits = rec.redundant_reads_after_write();
        assert_eq!(
            hits.len(),
            1,
            "only the insert-then-select-same-table pair should match"
        );
        assert_eq!(hits[0].0.seq, 0);
        assert_eq!(hits[0].1.seq, 1);
    }

    #[test]
    fn redundant_reads_after_write_empty_when_no_reread_follows() {
        let rec = super::QueryRecorder::from_events_for_testing(vec![
            make(0, QueryKind::Insert, Some("resource_group"), true),
            make(1, QueryKind::Select, Some("gts_type"), true), // different table -- not a re-read
        ]);
        assert!(rec.redundant_reads_after_write().is_empty());
    }

    #[test]
    fn dump_marks_tx_scope_transitions() {
        let rec = super::QueryRecorder::from_events_for_testing(vec![
            make(0, QueryKind::Select, Some("gts_type"), false),
            make(1, QueryKind::Insert, Some("resource_group"), true),
            make(2, QueryKind::Insert, Some("resource_group_closure"), true),
        ]);
        let dump = rec.dump();
        assert_eq!(
            dump.matches("[outside tx]").count(),
            1,
            "one transition into the outside-tx region:\n{dump}"
        );
        assert_eq!(
            dump.matches("[enter tx scope]").count(),
            1,
            "one transition into the tx region:\n{dump}"
        );
        assert!(dump.contains("resource_group_closure"));
    }

    #[test]
    fn failed_statements_returns_only_failed_events_in_order() {
        let rec = super::QueryRecorder::from_events_for_testing(vec![
            make(0, QueryKind::Select, Some("gts_type"), false),
            make_failed(1, QueryKind::Insert, Some("resource_group"), true),
            make(2, QueryKind::Update, Some("resource_group"), true),
            make_failed(3, QueryKind::Delete, Some("resource_group"), false),
        ]);
        let failed = rec.failed_statements();
        assert_eq!(
            failed.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![1, 3],
            "expected exactly the two failed events, in their original order"
        );
        assert!(failed.iter().all(|e| e.failed));
    }
}
