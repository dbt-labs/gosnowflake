package gosnowflake

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func int64Ptr(v int64) *int64 { return &v }

func TestExecResponseDataDecodesStats(t *testing.T) {
	testcases := []struct {
		name     string
		body     string
		expected *QueryResultStats
	}{
		{
			name: "ctas",
			body: `{"queryId":"q1","stats":{"numRowsInserted":3,"numRowsDeleted":0,"numRowsUpdated":0,"numDmlDuplicates":0}}`,
			expected: &QueryResultStats{
				NumRowsInserted:  int64Ptr(3),
				NumRowsDeleted:   int64Ptr(0),
				NumRowsUpdated:   int64Ptr(0),
				NumDmlDuplicates: int64Ptr(0),
			},
		},
		{
			name:     "merge reporting only the updated rows",
			body:     `{"queryId":"q2","stats":{"numRowsUpdated":2}}`,
			expected: &QueryResultStats{NumRowsUpdated: int64Ptr(2)},
		},
		{
			name:     "no stats object, as for a view",
			body:     `{"queryId":"q3"}`,
			expected: nil,
		},
		{
			name:     "empty stats object",
			body:     `{"queryId":"q4","stats":{}}`,
			expected: &QueryResultStats{},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var data execResponseData
			assertNilF(t, json.Unmarshal([]byte(tc.body), &data))
			assertDeepEqualE(t, data.Stats, tc.expected)
		})
	}
}

func statsTestConn(postQuery func(*execResponseData), get func(resultID string) *execResponseData) *snowflakeConn {
	postQueryMock := func(_ context.Context, _ *snowflakeRestful,
		_ *url.Values, _ map[string]string, _ []byte, _ time.Duration,
		_ UUID, _ *Config) (*execResponse, error) {
		data := &execResponseData{}
		postQuery(data)
		return &execResponse{Data: *data, Code: "0", Success: true}, nil
	}
	funcGetMock := func(_ context.Context, _ *snowflakeRestful, u *url.URL,
		_ map[string]string, _ time.Duration) (*http.Response, error) {
		// the result id is the next to last element of /queries/<id>/result
		data := get(u.Path)
		ba, err := json.Marshal(&execResponse{Data: *data, Code: "0", Success: true})
		if err != nil {
			panic(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: &fakeResponseBody{body: ba}}, nil
	}
	return &snowflakeConn{
		cfg: &Config{Params: map[string]*string{}},
		rest: &snowflakeRestful{
			FuncPostQuery: postQueryMock,
			FuncGet:       funcGetMock,
			TokenAccessor: getSimpleTokenAccessor(),
		},
		queryContextCache:   (&queryContextCache{}).init(),
		currentTimeProvider: defaultTimeProvider,
	}
}

func TestQueryArrowStreamExposesStats(t *testing.T) {
	t.Run("stats sent by the server", func(t *testing.T) {
		sc := statsTestConn(func(d *execResponseData) {
			d.QueryID = "q1"
			d.QueryResultFormat = "json"
			d.Stats = &QueryResultStats{NumRowsInserted: int64Ptr(3)}
		}, nil)
		loader, err := sc.QueryArrowStream(context.Background(), "create table t as select 1")
		assertNilF(t, err)
		provider, ok := loader.(QueryResultStatsProvider)
		assertTrueF(t, ok, "the loader should implement QueryResultStatsProvider")
		stats := provider.QueryResultStats()
		assertNotNilF(t, stats)
		assertNotNilF(t, stats.NumRowsInserted)
		assertEqualE(t, *stats.NumRowsInserted, int64(3))
		assertNilE(t, stats.NumRowsUpdated, "a count the server did not send must stay nil, not 0")
	})
	t.Run("no stats sent by the server", func(t *testing.T) {
		sc := statsTestConn(func(d *execResponseData) {
			d.QueryID = "q2"
			d.QueryResultFormat = "json"
		}, nil)
		loader, err := sc.QueryArrowStream(context.Background(), "create view v as select 1")
		assertNilF(t, err)
		assertNilE(t, loader.(QueryResultStatsProvider).QueryResultStats())
	})
}

func TestQueryArrowStreamMultiStatementStatsFollowTheResultSet(t *testing.T) {
	childStats := map[string]*QueryResultStats{
		"/queries/child1/result": {NumRowsInserted: int64Ptr(5)},
		"/queries/child2/result": nil,
		"/queries/child3/result": {NumRowsUpdated: int64Ptr(2)},
	}
	sc := statsTestConn(func(d *execResponseData) {
		d.QueryID = "parent"
		d.ResultIDs = "child1,child2,child3"
		// the parent response of a multi statement does not describe any statement
		d.Stats = &QueryResultStats{NumRowsInserted: int64Ptr(999)}
	}, func(path string) *execResponseData {
		stats, ok := childStats[path]
		assertTrueF(t, ok, "unexpected result path "+path)
		return &execResponseData{QueryResultFormat: "json", Stats: stats}
	})
	loader, err := sc.QueryArrowStream(context.Background(), "create table a as select 1; create view b as select 1; update c set x = 1")
	assertNilF(t, err)
	provider := loader.(QueryResultStatsProvider)

	// the first child is loaded while the loader is created
	stats := provider.QueryResultStats()
	assertNotNilF(t, stats)
	assertEqualE(t, *stats.NumRowsInserted, int64(5))

	assertNilF(t, loader.NextResultSet(context.Background()))
	assertNilE(t, provider.QueryResultStats(), "the second statement reported no stats")

	assertNilF(t, loader.NextResultSet(context.Background()))
	stats = provider.QueryResultStats()
	assertNotNilF(t, stats)
	assertEqualE(t, *stats.NumRowsUpdated, int64(2))
	assertNilE(t, stats.NumRowsInserted)
}
