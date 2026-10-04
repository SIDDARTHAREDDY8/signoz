package ruletypes

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qbtypes "github.com/SigNoz/signoz/pkg/types/querybuildertypes/querybuildertypesv5"
	"github.com/SigNoz/signoz/pkg/types/telemetrytypes"
)

// TestProcessRuleDefaults_ConvertsBuilderQueriesToV5Queries is the regression
// test for https://github.com/SigNoz/signoz/issues/10823.
//
// Rules created through POST /api/v1/rules may carry their queries in the
// legacy v4 `builderQueries` map shape inside condition.compositeQuery. The
// ruler's v5 evaluation path only reads the v5 `queries` array, so a rule
// stored with builderQueries populated (and queries empty) never fires — the
// query never reaches ClickHouse. processRuleDefaults must normalize
// builderQueries into queries on unmarshal so the rule becomes evaluatable.
func TestProcessRuleDefaults_ConvertsBuilderQueriesToV5Queries(t *testing.T) {
	// Payload shape taken verbatim from the issue's reproduction: a v5 rule
	// whose compositeQuery only carries builderQueries.
	body := []byte(`{
		"alert": "TestRule",
		"alertType": "LOGS_BASED_ALERT",
		"ruleType": "threshold_rule",
		"version": "v5",
		"evalWindow": "5m0s",
		"frequency": "1m0s",
		"condition": {
			"compositeQuery": {
				"queryType": "builder",
				"panelType": "graph",
				"builderQueries": {
					"A": {
						"queryName": "A",
						"stepInterval": 60,
						"dataSource": "logs",
						"aggregateOperator": "count",
						"aggregateAttribute": {"key": "", "dataType": "", "type": "", "isColumn": false},
						"filters": {"op": "AND", "items": []},
						"expression": "A",
						"disabled": false
					}
				}
			},
			"op": "1",
			"target": 1,
			"matchType": "4"
		},
		"labels": {"severity": "warning"},
		"annotations": {"description": "Test", "summary": "Test"},
		"disabled": false
	}`)

	var rule PostableRule
	require.NoError(t, json.Unmarshal(body, &rule))

	require.NotNil(t, rule.RuleCondition)
	require.NotNil(t, rule.RuleCondition.CompositeQuery)
	queries := rule.RuleCondition.CompositeQuery.Queries
	require.Len(t, queries, 1, "builderQueries must be normalized into queries so the ruler can evaluate the rule")

	env := queries[0]
	assert.Equal(t, qbtypes.QueryTypeBuilder, env.Type)

	spec, ok := env.Spec.(qbtypes.QueryBuilderQuery[qbtypes.LogAggregation])
	require.True(t, ok, "expected a logs builder query spec, got %T", env.Spec)
	assert.Equal(t, "A", spec.Name)
	assert.Equal(t, telemetrytypes.SignalLogs, spec.Signal)
	assert.False(t, spec.Disabled)
	require.Len(t, spec.Aggregations, 1, "count aggregateOperator must map to a count() aggregation")
	assert.Equal(t, "count()", spec.Aggregations[0].Expression)
}
