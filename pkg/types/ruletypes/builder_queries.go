package ruletypes

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	qbtypes "github.com/SigNoz/signoz/pkg/types/querybuildertypes/querybuildertypesv5"
)

// migrateBuilderQueriesToV5 converts the legacy v4 builderQueries map
// (query name -> v4 builder query body, as accepted by POST /api/v1/rules)
// into v5 query envelopes.
//
// It is a best-effort shape translation: queries that cannot be decoded or
// wrapped are skipped so that a single malformed entry does not poison the
// whole rule. Callers only fall back to this when no v5 queries are present,
// so v5 payloads are never rewritten.
//
// See https://github.com/SigNoz/signoz/issues/10823.
func migrateBuilderQueriesToV5(builderQueries map[string]json.RawMessage) []qbtypes.QueryEnvelope {
	if len(builderQueries) == 0 {
		return nil
	}

	// Sort names for a deterministic query order.
	names := make([]string, 0, len(builderQueries))
	for name := range builderQueries {
		names = append(names, name)
	}
	sort.Strings(names)

	envelopes := make([]qbtypes.QueryEnvelope, 0, len(names))
	for _, name := range names {
		var queryMap map[string]any
		if err := json.Unmarshal(builderQueries[name], &queryMap); err != nil {
			continue
		}
		normalizeV4BuilderQuery(queryMap)

		env := qbtypes.WrapInV5Envelope(name, queryMap, qbtypes.QueryTypeBuilder.StringValue())
		raw, err := json.Marshal(env)
		if err != nil {
			continue
		}
		var envelope qbtypes.QueryEnvelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			continue
		}
		envelopes = append(envelopes, envelope)
	}
	return envelopes
}

// normalizeV4BuilderQuery translates the v4 flat aggregation fields that
// WrapInV5Envelope does not cover into their v5 equivalents, in place,
// mirroring the codebase's own v4->v5 migration
// (pkg/transition/migrate_common.go createAggregations):
//   - logs/traces: aggregateOperator + aggregateAttribute.key ->
//     aggregations[0].expression (e.g. count -> "count()",
//     sum + "duration" -> "sum(duration)")
//   - metrics: aggregateAttribute.key -> aggregations[0].metricName plus
//     temporality/timeAggregation/spaceAggregation carried over
//     (spaceAggregation defaults to the aggregate operator, as in the v4
//     branch of the dashboard migrator).
//
// v4 filters ({op, items}) have no faithful v5 representation — v5 filters
// are a single expression string — so they are left unset rather than
// guessed. WrapInV5Envelope carries over the remaining shared fields
// (name, signal from dataSource, stepInterval, disabled, groupBy, orderBy,
// selectColumns, limit, offset, having, functions, legend).
func normalizeV4BuilderQuery(queryMap map[string]any) {
	if _, ok := queryMap["aggregations"]; ok {
		return
	}

	op, _ := queryMap["aggregateOperator"].(string)
	op = strings.ToLower(strings.TrimSpace(op))

	attr, _ := queryMap["aggregateAttribute"].(map[string]any)
	attrKey, _ := attr["key"].(string)

	dataSource, _ := queryMap["dataSource"].(string)

	if dataSource == "metrics" {
		aggregation := map[string]any{
			"metricName":       attrKey,
			"temporality":      queryMap["temporality"],
			"timeAggregation":  queryMap["timeAggregation"],
			"spaceAggregation": queryMap["spaceAggregation"],
		}
		if _, ok := aggregation["spaceAggregation"]; !ok || aggregation["spaceAggregation"] == nil {
			aggregation["spaceAggregation"] = op
		}
		if reduceTo, ok := queryMap["reduceTo"].(string); ok && reduceTo != "" {
			aggregation["reduceTo"] = reduceTo
		}
		queryMap["aggregations"] = []any{aggregation}
		return
	}

	if dataSource != "logs" && dataSource != "traces" {
		return
	}

	queryMap["aggregations"] = []any{
		map[string]any{"expression": v4AggregationExpression(op, attrKey)},
	}
}

// v4AggregationExpression mirrors transition.buildAggregationExpression for
// the logs/traces v4 aggregate operators.
func v4AggregationExpression(operator, key string) string {
	withKey := func(expr string) string {
		if key != "" {
			return fmt.Sprintf("%s(%s)", expr, key)
		}
		return fmt.Sprintf("%s()", expr)
	}

	switch operator {
	case "count":
		return "count()"
	case "sum_rate":
		if key != "" {
			return fmt.Sprintf("sum(rate(%s))", key)
		}
		return "sum(rate())"
	case "sum", "avg", "min", "max",
		"p05", "p10", "p20", "p25", "p50", "p75", "p90", "p95", "p99",
		"rate", "rate_sum", "rate_avg", "rate_min", "rate_max",
		"count_distinct":
		return withKey(operator)
	default:
		return "count()"
	}
}
