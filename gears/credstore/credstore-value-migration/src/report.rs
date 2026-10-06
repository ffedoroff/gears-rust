// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! What the tool prints, and the exit codes.
//!
//! Reports go to the `out` stream and never contain a secret value or a
//! fingerprint: rows are named by id, tenant and reference only.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::process::ExitCode;

use uuid::Uuid;

use crate::state::RowState;

/// The stream reports are written to.
pub type Out<'a> = &'a mut (dyn Write + Send);

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// `0`: finished.
    Success,
    /// `1`: aborted by an error; fix the cause and run the same command again.
    Failure,
    /// `2`: the operator has to decide something (the report says what).
    Decision,
}

impl Exit {
    /// The process exit code.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Decision => 2,
        }
    }
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        Self::from(exit.code())
    }
}

/// Writes one line to `out`; a stream that cannot be written to is logged, not
/// fatal.
pub fn emit(out: &mut dyn Write, line: fmt::Arguments<'_>) {
    if let Err(e) = writeln!(out, "{line}") {
        tracing::warn!(error = %e, "credstore value migration: cannot write to the output stream");
    }
}

/// `println!` for the run's output stream.
macro_rules! say {
    ($out:expr, $($arg:tt)*) => {
        $crate::report::emit($out, format_args!($($arg)*))
    };
}
pub(crate) use say;

/// Identifies a row in a report. Never carries a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowRef {
    /// Row id.
    pub id: Uuid,
    /// Tenant of the row.
    pub tenant_id: Uuid,
    /// Reference of the row.
    pub reference: String,
}

/// Prints `title: N` and one line per row.
pub fn print_rows(out: &mut dyn Write, title: &str, rows: &[(RowRef, RowState)]) {
    if rows.is_empty() {
        return;
    }
    emit(out, format_args!("{title}: {}", rows.len()));
    for (r, state) in rows {
        emit(
            out,
            format_args!(
                "  id={} tenant={} reference={} outcome={state}",
                r.id, r.tenant_id, r.reference
            ),
        );
    }
}

/// Prints the per-state tally of the progress table.
pub fn print_tally(out: &mut dyn Write, tally: &BTreeMap<RowState, usize>) {
    for state in RowState::ALL {
        if let Some(n) = tally.get(&state) {
            emit(out, format_args!("  {state}: {n}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_0_1_2() {
        assert_eq!(
            [Exit::Success, Exit::Failure, Exit::Decision].map(Exit::code),
            [0, 1, 2]
        );
        assert_eq!(ExitCode::from(Exit::Decision), ExitCode::from(2));
    }

    #[test]
    fn rows_are_printed_by_id_tenant_and_reference_only() {
        let mut buf = Vec::new();
        let row = RowRef {
            id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            reference: "db-password".to_owned(),
        };
        print_rows(&mut buf, "MISSING", &[(row, RowState::Missing)]);
        let text = String::from_utf8(buf).unwrap_or_default();
        assert!(text.starts_with("MISSING: 1\n"));
        assert!(text.contains("reference=db-password outcome=missing"));
    }
}
