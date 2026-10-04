package rules

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SigNoz/signoz/pkg/instrumentation/instrumentationtest"
	"github.com/SigNoz/signoz/pkg/types/ruletypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

// TestThresholdRule_PrepareQueryRange_ResolvesAPIStoredBuilderQueries is the
// ruler-level regression test for
// https://github.com/SigNoz/signoz/issues/10823.
//
// It builds a rule the way POST /api/v1/rules stores it — with the legacy v4
// builderQueries map populated and the v5 queries array absent — and asserts
// that the ruler's evaluation path (prepareQueryRange, used by
// buildAndRunQuery) resolves an executable query instead of yielding zero
// queries (which made the query never reach ClickHouse and the rule silently
// never fire).
func TestThresholdRule_PrepareQueryRange_ResolvesAPIStoredBuilderQueries(t *testing.T) {
	// Payload shape taken verbatim from the issue's reproduction.
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

	var postable ruletypes.PostableRule
	require.NoError(t, json.Unmarshal(body, &postable))
	require.NoError(t, postable.Validate(), "the API must accept the normalized rule")

	logger := instrumentationtest.New().Logger()
	externalURL := mustParseURL(t, "http://localhost:8080")

	rule, err := NewThresholdRule("10823", valuer.GenerateUUID(), &postable, nil, logger, externalURL)
	require.NoError(t, err)

	req, err := rule.prepareQueryRange(context.Background(), time.Now())
	require.NoError(t, err)
	require.NotNil(t, req)
	require.Len(t, req.CompositeQuery.Queries, 1,
		"the ruler evaluation path must resolve the API-stored builderQueries into an executable query")
	assert.Equal(t, "A", req.CompositeQuery.Queries[0].GetQueryName())
}
