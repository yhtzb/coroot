package collector

import (
	"context"
	"crypto/tls"
	"strings"
	"time"

	"github.com/ClickHouse/ch-go"
	"github.com/coroot/coroot/db"
)

const (
	ttlDays = "7"
)

func (c *Collector) migrate(ctx context.Context, cfg *db.IntegrationClickhouse) error {
	if cfg == nil {
		return nil
	}

	opts := ch.Options{
		Address:          cfg.Addr,
		Database:         cfg.Database,
		User:             cfg.Auth.User,
		Password:         cfg.Auth.Password,
		Compression:      ch.CompressionLZ4,
		ReadTimeout:      30 * time.Second,
		DialTimeout:      10 * time.Second,
		HandshakeTimeout: 10 * time.Second,
	}
	if cfg.TlsEnable {
		opts.TLS = &tls.Config{
			InsecureSkipVerify: cfg.TlsSkipVerify,
		}
	}
	cl, err := ch.Dial(ctx, opts)
	if err != nil {
		return err
	}
	defer cl.Close()

	for _, t := range tables {
		t = strings.ReplaceAll(t, "@ttl_days", ttlDays)
		err = cl.Do(ctx, ch.Query{Body: t})
		if err != nil {
			return err
		}
	}
	return nil
}

var (
	tables = []string{
		// 新建表 otel_logs。
		`
CREATE TABLE IF NOT EXISTS otel_logs (
     Timestamp DateTime64(9) CODEC(Delta, ZSTD(1)),
     TraceId String CODEC(ZSTD(1)),
     SpanId String CODEC(ZSTD(1)),
     TraceFlags UInt32 CODEC(ZSTD(1)),
     SeverityText LowCardinality(String) CODEC(ZSTD(1)),
     SeverityNumber Int32 CODEC(ZSTD(1)),
     ServiceName LowCardinality(String) CODEC(ZSTD(1)),
     Body String CODEC(ZSTD(1)),
     ResourceAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
     LogAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
     INDEX idx_trace_id TraceId TYPE bloom_filter(0.001) GRANULARITY 1,
     INDEX idx_res_attr_key mapKeys(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
     INDEX idx_res_attr_value mapValues(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
     INDEX idx_log_attr_key mapKeys(LogAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
     INDEX idx_log_attr_value mapValues(LogAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
     INDEX idx_body Body TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 1
) ENGINE MergeTree()
TTL toDateTime(Timestamp) + toIntervalDay(@ttl_days)
PARTITION BY toDate(Timestamp)
ORDER BY (ServiceName, SeverityText, toUnixTimestamp(Timestamp))
SETTINGS index_granularity=8192, ttl_only_drop_parts = 1
`,

		// 新建表 otel_traces。
		`
CREATE TABLE IF NOT EXISTS otel_traces (
     Timestamp DateTime64(9) CODEC(Delta, ZSTD(1)),
     TraceId String CODEC(ZSTD(1)),
     SpanId String CODEC(ZSTD(1)),
     ParentSpanId String CODEC(ZSTD(1)),
     TraceState String CODEC(ZSTD(1)),
     SpanName LowCardinality(String) CODEC(ZSTD(1)),
     SpanKind LowCardinality(String) CODEC(ZSTD(1)),
     ServiceName LowCardinality(String) CODEC(ZSTD(1)),
     ResourceAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
     SpanAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
     Duration Int64 CODEC(ZSTD(1)),
     StatusCode LowCardinality(String) CODEC(ZSTD(1)),
     StatusMessage String CODEC(ZSTD(1)),
     Events Nested (
         Timestamp DateTime64(9),
         Name LowCardinality(String),
         Attributes Map(LowCardinality(String), String)
     ) CODEC(ZSTD(1)),
     Links Nested (
         TraceId String,
         SpanId String,
         TraceState String,
         Attributes Map(LowCardinality(String), String)
     ) CODEC(ZSTD(1)),
     INDEX idx_trace_id TraceId TYPE bloom_filter(0.001) GRANULARITY 1,
     INDEX idx_res_attr_key mapKeys(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
     INDEX idx_res_attr_value mapValues(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
     INDEX idx_span_attr_key mapKeys(SpanAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
     INDEX idx_span_attr_value mapValues(SpanAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
     INDEX idx_duration Duration TYPE minmax GRANULARITY 1
) ENGINE MergeTree()
TTL toDateTime(Timestamp) + toIntervalDay(@ttl_days)
PARTITION BY toDate(Timestamp)
ORDER BY (ServiceName, SpanName, toUnixTimestamp(Timestamp))
SETTINGS index_granularity=8192, ttl_only_drop_parts = 1`,

		// 新建物化列 NetSockPeerAddr。
		`
ALTER TABLE otel_traces ADD COLUMN IF NOT EXISTS NetSockPeerAddr LowCardinality(String) 
MATERIALIZED concat(SpanAttributes['net.peer.name'], ':', SpanAttributes['net.peer.port']) CODEC(ZSTD(1))`,

		// 新建表 l7_events_ss。
		`
CREATE TABLE IF NOT EXISTS l7_events_ss (
     Timestamp DateTime64(9) CODEC(Delta, ZSTD(1)),
     Duration Int64 CODEC(ZSTD(1)),
     ContainerId LowCardinality(String) CODEC(ZSTD(1)),
     TgidRead LowCardinality(String) CODEC(ZSTD(1)),
     TgidWrite LowCardinality(String) CODEC(ZSTD(1)),
     StatementId UInt32 CODEC(ZSTD(1))
    )
ENGINE MergeTree()
TTL toDateTime(Timestamp) + toIntervalDay(@ttl_days)
PARTITION BY toDate(Timestamp)
ORDER BY (toUnixTimestamp(Timestamp))`,

		// 新建表 profiling_stacks。
		`
CREATE TABLE IF NOT EXISTS profiling_stacks (
	ServiceName LowCardinality(String) CODEC(ZSTD(1)),
	Hash UInt64 CODEC(ZSTD(1)),
	LastSeen DateTime64(9) CODEC(Delta, ZSTD(1)),
	Stack Array(String) CODEC(ZSTD(1))
) 
ENGINE ReplacingMergeTree()
PRIMARY KEY (ServiceName, Hash)
TTL toDateTime(LastSeen) + toIntervalDay(@ttl_days)
PARTITION BY toDate(LastSeen)
ORDER BY (ServiceName, Hash)`,

		// 新建表 profiling_samples。
		`
CREATE TABLE IF NOT EXISTS profiling_samples (
	ServiceName LowCardinality(String) CODEC(ZSTD(1)),
    Type LowCardinality(String) CODEC(ZSTD(1)),
	Start DateTime64(9) CODEC(Delta, ZSTD(1)),
	End DateTime64(9) CODEC(Delta, ZSTD(1)),
	Labels Map(LowCardinality(String), String) CODEC(ZSTD(1)),
	StackHash UInt64 CODEC(ZSTD(1)),
	Value Int64 CODEC(ZSTD(1))
) ENGINE MergeTree()
TTL toDateTime(Start) + toIntervalDay(@ttl_days)
PARTITION BY toDate(Start)
ORDER BY (ServiceName, Type, toUnixTimestamp(Start), toUnixTimestamp(End))`,

		// 新建表 profiling_profiles。
		`
CREATE TABLE IF NOT EXISTS profiling_profiles (
    ServiceName LowCardinality(String) CODEC(ZSTD(1)),
    Type LowCardinality(String) CODEC(ZSTD(1)),
    LastSeen DateTime64(9) CODEC(Delta, ZSTD(1))
)
ENGINE ReplacingMergeTree()
PRIMARY KEY (ServiceName, Type)
TTL toDateTime(LastSeen) + toIntervalDay(@ttl_days)
PARTITION BY toDate(LastSeen)`,

		// 新建物化视图 profiling_profiles_mv，为 profiling_profiles 维护 max range。
		`
CREATE MATERIALIZED VIEW IF NOT EXISTS profiling_profiles_mv TO profiling_profiles AS 
SELECT ServiceName, Type, max(End) AS LastSeen FROM profiling_samples group by ServiceName, Type`,
	}
)
