package model

import (
	"strings"
	"testing"

	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/schema"
)

// renderPostgresSQL renders a bun select query using the Postgres dialect so
// the generated SQL can be validated without a live database.
func renderPostgresSQL(t *testing.T, q *bun.SelectQuery) string {
	t.Helper()

	fmter := schema.NewFormatter(pgdialect.New())
	b, err := q.AppendQuery(fmter, nil)
	if err != nil {
		t.Fatalf("failed to render postgres query: %v", err)
	}
	return string(b)
}

// TestKeepOnlyLast50AgentsSubquery_PostgresValid is a regression test for
// https://github.com/SigNoz/signoz/issues/12308.
//
// The agent retention subquery used SELECT DISTINCT with ORDER BY created_at
// while created_at was not in the select list. Postgres rejects that
// combination (SQLSTATE 42P10), so KeepOnlyLast50Agents never ran under
// SIGNOZ_SQLSTORE_PROVIDER=postgres. The generated query must therefore be
// acceptable to Postgres: it must not use SELECT DISTINCT with an ORDER BY on
// a non-selected column.
func TestKeepOnlyLast50AgentsSubquery_PostgresValid(t *testing.T) {
	// NewDB is never used to execute anything here; it only provides the
	// Postgres dialect for rendering the query text. The nil *sql.DB is never
	// touched by AppendQuery, so it is safe to omit db.Close().
	db := bun.NewDB(nil, pgdialect.New())

	orgID := valuer.MustNewUUID("123e4567-e89b-12d3-a456-426614174000")
	sql := renderPostgresSQL(t, lastNAgentsSubquery(db, orgID, 50))
	t.Logf("generated subquery: %s", sql)

	upper := strings.ToUpper(sql)
	if strings.Contains(upper, "DISTINCT") {
		// Postgres: "for SELECT DISTINCT, ORDER BY expressions must appear in
		// select list" (SQLSTATE 42P10).
		t.Errorf("subquery uses SELECT DISTINCT with ORDER BY on a non-selected column, which Postgres rejects (SQLSTATE 42P10): %s", sql)
	}

	// Sanity checks: the retention semantics must be preserved — the most
	// recent agents (by created_at) stay, everything else is deleted.
	if !strings.Contains(upper, "ORDER BY") || !strings.Contains(upper, "CREATED_AT") {
		t.Errorf("subquery must order by created_at to keep the most recent agents: %s", sql)
	}
	if !strings.Contains(upper, "LIMIT 50") {
		t.Errorf("subquery must limit to the 50 most recent agents: %s", sql)
	}
	if !strings.Contains(upper, "ORG_ID") {
		t.Errorf("subquery must filter by org_id: %s", sql)
	}
}
