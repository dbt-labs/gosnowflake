package gosnowflake

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func (sc *snowflakeConn) isClientSessionKeepAliveEnabled() bool {
	paramsMutex.Lock()
	v, ok := sc.cfg.Params[sessionClientSessionKeepAlive]
	paramsMutex.Unlock()
	if !ok {
		return false
	}
	return strings.Compare(*v, "true") == 0
}

func (sc *snowflakeConn) getClientSessionKeepAliveHeartbeatFrequency() (time.Duration, bool) {
	paramsMutex.Lock()
	v, ok := sc.cfg.Params[sessionClientSessionKeepAliveHeartbeatFrequency]
	paramsMutex.Unlock()

	if !ok {
		return 0, false
	}

	num, err := strconv.Atoi(*v)
	if err != nil {
		logger.WithError(err).Warnf("Failed to parse client session keepalive heartbeat frequency. Falling back to default.")
		return 0, false
	}

	return time.Duration(num) * time.Second, true
}

func (sc *snowflakeConn) startHeartBeat() {
	if sc.cfg != nil && !sc.isClientSessionKeepAliveEnabled() {
		return
	}
	if sc.rest != nil {
		if heartbeatFrequency, ok := sc.getClientSessionKeepAliveHeartbeatFrequency(); ok {
			sc.rest.HeartBeat = newHeartBeat(sc.rest, heartbeatFrequency)
		} else {
			sc.rest.HeartBeat = newDefaultHeartBeat(sc.rest)
		}
		sc.rest.HeartBeat.start()
	}
}

func (sc *snowflakeConn) stopHeartBeat() {
	if sc.cfg != nil && !sc.isClientSessionKeepAliveEnabled() {
		return
	}
	if sc.rest != nil && sc.rest.HeartBeat != nil {
		sc.rest.HeartBeat.stop()
	}
}

func (sc *snowflakeConn) getArrayBindStageThreshold() int {
	paramsMutex.Lock()
	v, ok := sc.cfg.Params[sessionArrayBindStageThreshold]
	paramsMutex.Unlock()
	if !ok {
		return 0
	}
	num, err := strconv.Atoi(*v)
	if err != nil {
		return 0
	}
	return num
}

func (sc *snowflakeConn) connectionTelemetry(cfg *Config) {
	data := &telemetryData{
		Message: map[string]string{
			typeKey:          connectionParameters,
			sourceKey:        telemetrySource,
			driverTypeKey:    "Go",
			driverVersionKey: SnowflakeGoDriverVersion,
			golangVersionKey: runtime.Version(),
		},
		Timestamp: time.Now().UnixNano() / int64(time.Millisecond),
	}
	paramsMutex.Lock()
	for k, v := range cfg.Params {
		data.Message[k] = *v
	}
	paramsMutex.Unlock()
	if err := sc.telemetry.addLog(data); err != nil {
		logger.WithContext(sc.ctx).Warn(err)
	}
	if err := sc.telemetry.sendBatch(); err != nil {
		logger.WithContext(sc.ctx).Warn(err)
	}
}

// processFileTransfer creates a snowflakeFileTransferAgent object to process
// any PUT/GET commands with their specified options
func (sc *snowflakeConn) processFileTransfer(
	ctx context.Context,
	data *execResponse,
	query string,
	isInternal bool) (
	*execResponse, error) {
	options := &SnowflakeFileTransferOptions{
		RaisePutGetError: true,
	}
	sfa := snowflakeFileTransferAgent{
		ctx:          ctx,
		sc:           sc,
		data:         &data.Data,
		command:      query,
		options:      options,
		streamBuffer: new(bytes.Buffer),
	}
	fs, err := getFileStream(ctx)
	if err != nil {
		return nil, err
	}
	if fs != nil {
		sfa.sourceStream = fs
		if isInternal {
			sfa.data.AutoCompress = false
		}
	}
	if op := getFileTransferOptions(ctx); op != nil {
		sfa.options = op
	}
	if sfa.options.MultiPartThreshold == 0 {
		sfa.options.MultiPartThreshold = multiPartThreshold
		// for streaming download, use a smaller default part size
		if sfa.commandType == downloadCommand && sfa.options.GetFileToStream {
			sfa.options.MultiPartThreshold = streamingMultiPartThreshold
		}
	}
	if err := sfa.execute(); err != nil {
		return nil, err
	}
	data, err = sfa.result()
	if err != nil {
		return nil, err
	}
	if sfa.options.GetFileToStream {
		if err := writeFileStream(ctx, sfa.streamBuffer); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func getFileStream(ctx context.Context) (io.Reader, error) {
	s := ctx.Value(fileStreamFile)
	if s == nil {
		return nil, nil
	}
	r, ok := s.(io.Reader)
	if !ok {
		return nil, errors.New("incorrect io.Reader")
	}
	return r, nil
}

func getFileTransferOptions(ctx context.Context) *SnowflakeFileTransferOptions {
	v := ctx.Value(fileTransferOptions)
	if v == nil {
		return nil
	}
	o, ok := v.(*SnowflakeFileTransferOptions)
	if !ok {
		return nil
	}
	return o
}

func writeFileStream(ctx context.Context, streamBuf *bytes.Buffer) error {
	s := ctx.Value(fileGetStream)
	w, ok := s.(io.Writer)
	if !ok {
		return errors.New("expected an io.Writer")
	}
	_, err := streamBuf.WriteTo(w)
	if err != nil {
		return err
	}
	return nil
}

func (sc *snowflakeConn) populateSessionParameters(parameters []nameValueParameter) {
	// other session parameters (not all)
	logger.WithContext(sc.ctx).Tracef("params: %#v", parameters)
	for _, param := range parameters {
		v := ""
		switch param.Value.(type) {
		case int64:
			if vv, ok := param.Value.(int64); ok {
				v = strconv.FormatInt(vv, 10)
			}
		case float64:
			if vv, ok := param.Value.(float64); ok {
				v = strconv.FormatFloat(vv, 'g', -1, 64)
			}
		case bool:
			if vv, ok := param.Value.(bool); ok {
				v = strconv.FormatBool(vv)
			}
		default:
			if vv, ok := param.Value.(string); ok {
				v = vv
			}
		}
		logger.WithContext(sc.ctx).Debugf("parameter. name: %v, value: %v", param.Name, v)
		paramsMutex.Lock()
		sc.cfg.Params[strings.ToLower(param.Name)] = &v
		paramsMutex.Unlock()
	}
}

func isAsyncMode(ctx context.Context) bool {
	val := ctx.Value(asyncMode)
	if val == nil {
		return false
	}
	a, ok := val.(bool)
	return ok && a
}

func isDescribeOnly(ctx context.Context) bool {
	v := ctx.Value(describeOnly)
	if v == nil {
		return false
	}
	d, ok := v.(bool)
	return ok && d
}

func isInternal(ctx context.Context) bool {
	v := ctx.Value(internalQuery)
	if v == nil {
		return false
	}
	d, ok := v.(bool)
	return ok && d
}

func setResultType(ctx context.Context, resType resultType) context.Context {
	return context.WithValue(ctx, snowflakeResultType, resType)
}

func getResultType(ctx context.Context) resultType {
	return ctx.Value(snowflakeResultType).(resultType)
}

// isDml returns true if the statement type code is in the range of DML.
func isDml(v int64) bool {
	return statementTypeIDDml <= v && v <= statementTypeIDMultiTableInsert
}

func isDql(data *execResponseData) bool {
	return data.StatementTypeID == statementTypeIDSelect && !isMultiStmt(data)
}

func updateRows(data execResponseData) (int64, error) {
	if data.RowSet == nil {
		return 0, nil
	}
	var count int64
	for i, n := 0, len(data.RowType); i < n; i++ {
		v, err := strconv.ParseInt(*data.RowSet[0][i], 10, 64)
		if err != nil {
			return -1, err
		}
		count += v
	}
	return count, nil
}

// isMultiStmt returns true if the statement code is of type multistatement
// Note that the statement type code is also equivalent to type INSERT, so an
// additional check of the name is required
func isMultiStmt(data *execResponseData) bool {
	var isMultistatementByReturningSelect = data.StatementTypeID == statementTypeIDSelect && data.RowType[0].Name == "multiple statement execution"
	return isMultistatementByReturningSelect || data.StatementTypeID == statementTypeIDMultistatement
}

func getResumeQueryID(ctx context.Context) (string, error) {
	val := ctx.Value(fetchResultByID)
	if val == nil {
		return "", nil
	}
	strVal, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("failed to cast val %+v to string", val)
	}
	// so there is a queryID in context for which we want to fetch the result
	if !queryIDRegexp.MatchString(strVal) {
		return strVal, &SnowflakeError{
			Number:  ErrQueryIDFormat,
			Message: "Invalid QID",
			QueryID: strVal,
		}
	}
	return strVal, nil
}

// returns snowflake chunk downloader by default or stream based chunk
// downloader if option provided through context
func populateChunkDownloader(
	ctx context.Context,
	sc *snowflakeConn,
	data execResponseData) chunkDownloader {
	if useStreamDownloader(ctx) && resultFormat(data.QueryResultFormat) == jsonFormat {
		// stream chunk downloading only works for row based data formats, i.e. json
		fetcher := &httpStreamChunkFetcher{
			ctx:           ctx,
			client:        sc.rest.Client,
			clientIP:      sc.cfg.ClientIP,
			headers:       data.ChunkHeaders,
			maxRetryCount: sc.rest.MaxRetryCount,
			qrmk:          data.Qrmk,
			timeout:       sc.rest.RequestTimeout,
		}
		return newStreamChunkDownloader(ctx, fetcher, data.Total, data.RowType,
			data.RowSet, data.Chunks)
	}

	return &snowflakeChunkDownloader{
		sc:                 sc,
		ctx:                ctx,
		pool:               getAllocator(ctx),
		CurrentChunk:       make([]chunkRowType, len(data.RowSet)),
		ChunkMetas:         data.Chunks,
		Total:              data.Total,
		TotalRowIndex:      int64(-1),
		CellCount:          len(data.RowType),
		Qrmk:               data.Qrmk,
		QueryResultFormat:  data.QueryResultFormat,
		ChunkHeader:        data.ChunkHeaders,
		FuncDownload:       downloadChunk,
		FuncDownloadHelper: downloadChunkHelper,
		FuncGet:            getChunk,
		RowSet: rowSetType{
			RowType:      data.RowType,
			JSON:         data.RowSet,
			RowSetBase64: data.RowSetBase64,
		},
	}
}

// checkIsPrivateLink reports whether host is a recognized PrivateLink endpoint.
func checkIsPrivateLink(host string) bool {
	normalized := normalizeSnowflakeHost(host)
	return isLdhHost(normalized) && isSnowflakeHost(normalized) && strings.Contains(normalized, ".privatelink.")
}

// normalizeSnowflakeHost trims whitespace, folds ASCII case, removes the port, and
// strips one trailing dot before applying the hostname allowlist.
func normalizeSnowflakeHost(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}, s)
	if idx := strings.IndexByte(s, ':'); idx >= 0 {
		s = s[:idx]
	}
	s = strings.TrimSuffix(s, ".")
	return s
}

// isLdhHost returns true if the already-normalized host contains only
// LDH characters ([a-z0-9_-] per label, separated by '.'). Each label must
// be non-empty.
//
// This is an allow-list, not a block-list. Enumerating forbidden characters
// does not work: URL parsers variously terminate the authority at a space,
// semicolon, quote, percent-escape, or a full-width look-alike of '.', '#',
// or '?'. A host whose trailing labels are a recognized Snowflake domain can
// still begin with an unrelated name, so a parser stopping early resolves
// that unrelated name instead.
func isLdhHost(normalized string) bool {
	if normalized == "" {
		return false
	}
	labelLen := 0
	for _, c := range normalized {
		switch {
		case c == '.':
			if labelLen == 0 {
				return false
			}
			labelLen = 0
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_':
			labelLen++
		default:
			return false
		}
	}
	return labelLen > 0
}

// isSnowflakeHost returns true if the already-normalized host ends at a
// recognized Snowflake domain suffix, anchored at a label boundary.
func isSnowflakeHost(normalized string) bool {
	for _, s := range []string{"snowflakecomputing.com", "snowflakecomputing.cn", "snowflakecomputing.mil"} {
		if normalized == s || strings.HasSuffix(normalized, "."+s) {
			return true
		}
	}
	return false
}

func isStatementContext(ctx context.Context) bool {
	v := ctx.Value(executionType)
	return v == executionTypeStatement
}
