use anyhow::{Result, anyhow};
use sqlparser::ast::{SetExpr, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// Validates that a SQL query is read-only before it is sent to a readonly database.
///
/// Defense-in-depth counterpart to the Postgres-level `default_transaction_read_only`
/// session setting. Two structural checks:
/// 1. Only a single statement is permitted — blocks stacked writes like `SELECT 1; DROP TABLE t`.
/// 2. The statement must be a SELECT-type query — blocks DML/DDL at the top level and in CTEs.
///
/// Fail-closed: unparseable SQL is rejected. The Postgres session-level enforcement is the
/// primary guard; this module provides fast, clear pre-flight rejection with precise messages.
pub fn validate_readonly_query(sql: &str) -> Result<()> {
    let dialect = PostgreSqlDialect {};
    let statements = Parser::parse_sql(&dialect, sql)
        .map_err(|e| anyhow!("Security Error: cannot parse SQL query — {}", e))?;

    match statements.len() {
        0 => Err(anyhow!(
            "Security Error: empty query is not permitted in readonly mode"
        )),
        1 => check_statement_readonly(&statements[0]),
        _ => Err(anyhow!(
            "Security Error: multiple statements are not permitted in readonly mode. \
             Only a single SELECT query is allowed."
        )),
    }
}

fn check_statement_readonly(stmt: &Statement) -> Result<()> {
    match stmt {
        Statement::Query(query) => {
            if let Some(with) = &query.with {
                for cte in &with.cte_tables {
                    check_set_expr_readonly(&cte.query.body)?;
                }
            }
            check_set_expr_readonly(&query.body)
        }
        Statement::Explain {
            analyze, statement, ..
        } => {
            if *analyze {
                return Err(anyhow!(
                    "Security Error: EXPLAIN ANALYZE is not permitted in readonly mode \
                     because it executes the query and may have side effects."
                ));
            }
            check_statement_readonly(statement)
        }
        _ => Err(anyhow!(
            "Security Error: only SELECT queries are allowed in readonly mode. \
             DML and DDL statements (INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, …) are prohibited."
        )),
    }
}

fn check_set_expr_readonly(expr: &SetExpr) -> Result<()> {
    match expr {
        SetExpr::Select(_) => Ok(()),
        SetExpr::Query(q) => {
            if let Some(with) = &q.with {
                for cte in &with.cte_tables {
                    check_set_expr_readonly(&cte.query.body)?;
                }
            }
            check_set_expr_readonly(&q.body)
        }
        SetExpr::SetOperation { left, right, .. } => {
            check_set_expr_readonly(left)?;
            check_set_expr_readonly(right)
        }
        SetExpr::Values(_) => Ok(()),
        _ => Err(anyhow!(
            "Security Error: write operations (INSERT/UPDATE/DELETE) are not permitted \
             in readonly mode, including inside CTEs."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── queries that must be ALLOWED ─────────────────────────────────────────

    #[test]
    fn allows_plain_select() {
        assert!(validate_readonly_query("SELECT 1").is_ok());
        assert!(validate_readonly_query("SELECT * FROM users").is_ok());
        assert!(
            validate_readonly_query(
                "SELECT id, name FROM orders WHERE status = 'active' LIMIT 100"
            )
            .is_ok()
        );
    }

    #[test]
    fn allows_select_with_leading_block_comment() {
        // Leading /* */ comment must not defeat the guard (old substring check bypass).
        assert!(validate_readonly_query("/* find all users */ SELECT * FROM users").is_ok());
    }

    #[test]
    fn allows_select_with_leading_line_comment() {
        assert!(validate_readonly_query("-- get count\nSELECT COUNT(*) FROM logs").is_ok());
    }

    #[test]
    fn allows_readonly_cte() {
        assert!(
            validate_readonly_query(
                "WITH active AS (SELECT * FROM users WHERE active = true) SELECT * FROM active"
            )
            .is_ok()
        );
    }

    #[test]
    fn allows_explain_without_analyze() {
        assert!(validate_readonly_query("EXPLAIN SELECT * FROM users").is_ok());
    }

    #[test]
    fn allows_select_with_column_named_delete() {
        // A column named 'delete_flag' must not be flagged as a write.
        assert!(validate_readonly_query("SELECT delete_flag, update_ts FROM audit_log").is_ok());
    }

    #[test]
    fn allows_union_select() {
        assert!(validate_readonly_query("SELECT id FROM a UNION ALL SELECT id FROM b").is_ok());
    }

    // ── queries that must be REJECTED ────────────────────────────────────────

    #[test]
    fn blocks_plain_delete() {
        assert!(validate_readonly_query("DELETE FROM users WHERE id = 1").is_err());
    }

    #[test]
    fn blocks_plain_insert() {
        assert!(validate_readonly_query("INSERT INTO t (a) VALUES (1)").is_err());
    }

    #[test]
    fn blocks_plain_update() {
        assert!(validate_readonly_query("UPDATE users SET name = 'x' WHERE id = 1").is_err());
    }

    #[test]
    fn blocks_drop_table() {
        assert!(validate_readonly_query("DROP TABLE users").is_err());
    }

    #[test]
    fn blocks_stacked_statements_with_semicolon() {
        // SELECT 1;DROP TABLE — the old substring check missed this because ";drop " ≠ " drop ".
        assert!(validate_readonly_query("SELECT 1; DROP TABLE users").is_err());
        assert!(validate_readonly_query("SELECT 1;DELETE FROM users").is_err());
        assert!(validate_readonly_query("SELECT 1;INSERT INTO t VALUES (1)").is_err());
    }

    #[test]
    fn blocks_comment_prefixed_write() {
        // A leading comment before a DML statement must still be blocked.
        assert!(validate_readonly_query("/* safe */ DELETE FROM users").is_err());
        assert!(validate_readonly_query("-- comment\nUPDATE users SET active = false").is_err());
    }

    #[test]
    fn blocks_explain_analyze() {
        // EXPLAIN ANALYZE executes the query and may carry side effects.
        assert!(validate_readonly_query("EXPLAIN ANALYZE SELECT * FROM users").is_err());
    }

    #[test]
    fn blocks_write_in_cte() {
        // Data-modifying CTE hidden behind a SELECT must be caught — either by the
        // AST check (if sqlparser parses it) or by the parser failing (fail-closed).
        let result =
            validate_readonly_query("WITH x AS (DELETE FROM users RETURNING *) SELECT * FROM x");
        assert!(
            result.is_err(),
            "data-modifying CTE must be rejected, got Ok"
        );
    }

    #[test]
    fn blocks_case_variant_write() {
        assert!(validate_readonly_query("delete from users").is_err());
        assert!(validate_readonly_query("INSERT into t values (1)").is_err());
        assert!(validate_readonly_query("Update users set x=1").is_err());
    }
}
