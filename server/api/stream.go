// Copyright 2022 Woodpecker Authors
// Copyright 2018 Drone.IO Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"go.woodpecker-ci.org/woodpecker/v3/server"
	"go.woodpecker-ci.org/woodpecker/v3/server/logging"
	"go.woodpecker-ci.org/woodpecker/v3/server/model"
	"go.woodpecker-ci.org/woodpecker/v3/server/pubsub"
	"go.woodpecker-ci.org/woodpecker/v3/server/router/middleware/session"
	"go.woodpecker-ci.org/woodpecker/v3/server/store"
)

const (
	// How many batches of logs to keep for each client before starting to
	// drop them if the client is not consuming them faster than they arrive.
	maxQueuedBatchesPerClient int = 30

	// Time between keepalive pings sent to the client.
	idlePingTime = time.Second * 30
)

// wsAcceptOptions are the options used for all WebSocket upgrades in this package.
//
// InsecureSkipVerify is set because the existing CORS / origin policy is enforced
// at the router/middleware layer, matching the behavior of the SSE endpoints which
// do not perform Origin checks themselves.
var wsAcceptOptions = &websocket.AcceptOptions{
	InsecureSkipVerify: true,
	// CompressionMode left at default (disabled) — payloads are small JSON messages,
	// and disabling compression avoids the per-message-deflate overhead.
}

// ============================================================================
// Shared transport-agnostic helpers
// ============================================================================

// buildEventTopics computes the set of pubsub topics a connected client should
// be subscribed to for the global event stream: the public topic plus a topic
// per repo the user has access to.
func buildEventTopics(c *gin.Context) map[string]struct{} {
	topics := map[string]struct{}{
		pubsub.PublicTopic: {},
	}
	user := session.User(c)
	if user != nil {
		repos, _ := store.FromContext(c).RepoList(user, false, true, nil)
		for _, r := range repos {
			topics[pubsub.GetRepoTopic(r)] = struct{}{}
		}
	}
	return topics
}

// stepLoadError carries a validation/lookup failure from loadStepFromRequest in
// a form each transport can map to its native error shape.
//
// httpStatus is what the WebSocket handler returns before upgrading.
// sseMessage is what the SSE handler writes into its error event frame.
type stepLoadError struct {
	httpStatus int
	sseMessage string
	cause      error
}

func (e *stepLoadError) Error() string {
	if e.cause != nil {
		return e.sseMessage + ": " + e.cause.Error()
	}
	return e.sseMessage
}

// loadStepFromRequest parses the pipeline and step path parameters, looks up
// the corresponding step, and verifies it's in a state where streaming logs
// makes sense. Returns a typed error so each transport can render it
// appropriately.
func loadStepFromRequest(c *gin.Context) (*model.Step, error) {
	_store := store.FromContext(c)
	repo := session.Repo(c)

	pipelineNum, err := strconv.ParseInt(c.Param("pipeline"), 10, 64)
	if err != nil {
		return nil, &stepLoadError{httpStatus: http.StatusBadRequest, sseMessage: "pipeline number invalid", cause: err}
	}
	pl, err := _store.GetPipelineNumber(repo, pipelineNum)
	if err != nil {
		return nil, &stepLoadError{httpStatus: http.StatusNotFound, sseMessage: "pipeline not found", cause: err}
	}

	stepID, err := strconv.ParseInt(c.Param("step_id"), 10, 64)
	if err != nil {
		return nil, &stepLoadError{httpStatus: http.StatusBadRequest, sseMessage: "step id invalid", cause: err}
	}
	step, err := _store.StepLoad(pl.ID, stepID)
	if err != nil {
		return nil, &stepLoadError{httpStatus: http.StatusNotFound, sseMessage: "process not found", cause: err}
	}

	if step.State != model.StatusPending && step.State != model.StatusRunning {
		return nil, &stepLoadError{httpStatus: http.StatusConflict, sseMessage: "step not running (anymore)"}
	}
	return step, nil
}

// runEventProducer subscribes to the given pubsub topics and returns a channel
// of serialized event payloads. The caller owns ctx; when ctx is cancelled the
// subscription terminates. Any subscribe error cancels ctx via the supplied
// cancel function (with the error as the cause).
func runEventProducer(
	ctx context.Context,
	cancel context.CancelCauseFunc,
	topics map[string]struct{},
) <-chan []byte {
	out := make(chan []byte, 10)
	go func() {
		err := server.Config.Services.Scheduler.Subscribe(ctx, topics,
			func(m pubsub.Message) {
				select {
				case <-ctx.Done():
				case out <- m.Data:
				}
			})
		cancel(err)
	}()
	return out
}

// runLogProducer opens the log stream for the given step, spawns a tail
// goroutine and a marshal pump, and returns a channel of JSON-encoded log
// entries. On a failure to open the stream the returned error is non-nil and
// no goroutines are started. When the tail completes the supplied cancel is
// invoked (with context.Canceled cause on clean EOF) — transports use that
// signal to send their EOF marker.
func runLogProducer(
	ctx context.Context,
	cancel context.CancelCauseFunc,
	stepID int64,
) (<-chan []byte, error) {
	if err := server.Config.Services.Logs.Open(ctx, stepID); err != nil {
		return nil, err
	}

	out := make(chan []byte, 10)
	go func() {
		batches := make(logging.LogChan, maxQueuedBatchesPerClient)

		var innerDone sync.WaitGroup
		innerDone.Add(1)
		go func() {
			defer innerDone.Done()
			for entries := range batches {
				for _, entry := range entries {
					ee, err := json.Marshal(entry)
					if err != nil {
						log.Error().Err(err).Msg("unable to serialize log entry")
						continue
					}
					select {
					case <-ctx.Done():
						return
					case out <- ee:
					}
				}
			}
		}()

		err := server.Config.Services.Logs.Tail(ctx, stepID, batches)
		if err != nil {
			log.Error().Err(err).Msg("tail of logs failed")
		}

		close(batches)
		innerDone.Wait()
		cancel(err)
	}()
	return out, nil
}

// pumpStream is the shared consumer loop used by both SSE and WebSocket
// handlers. It reads payloads from src and forwards them via onData, sending
// onPing every idlePingTime to keep the connection alive.
//
// The loop exits when:
//   - ctx is cancelled (the producer finished or errored);
//   - requestCtx is cancelled (the client went away);
//   - onData or onPing returns a non-nil error (the transport-specific write
//     failed and the connection should be torn down).
//
// The transport handler is responsible for any post-loop signaling (e.g.
// writing an SSE EOF event or sending a WebSocket close frame) — this
// function is intentionally pure plumbing.
func pumpStream(
	ctx context.Context,
	requestCtx context.Context,
	src <-chan []byte,
	onData func(buf []byte) error,
	onPing func() error,
) {
	pingTicker := time.NewTicker(idlePingTime)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-requestCtx.Done():
			return
		case <-pingTicker.C:
			if err := onPing(); err != nil {
				return
			}
		case buf, ok := <-src:
			if !ok {
				return
			}
			if err := onData(buf); err != nil {
				return
			}
		}
	}
}

// ============================================================================
// SSE handlers
// ============================================================================

// EventStreamSSE
//
//	@Summary		Stream events like pipeline updates
//	@Description	With quic and http2 support
//	@Router			/stream/sse/events [get]
//	@Produce		plain
//	@Success		200
//	@Tags			Events
func EventStreamSSE(c *gin.Context) {
	rw := c.Writer
	flusher, ok := rw.(http.Flusher)
	if !ok {
		c.String(http.StatusInternalServerError, "Streaming not supported")
		return
	}
	sseHeaders(c, "no-store")

	// Initial ping so proxies/clients commit to the long-lived response.
	logWriteStringErr(io.WriteString(rw, ": ping\n\n"))
	flusher.Flush()

	log.Debug().Msg("user feed: connection opened")

	ctx, cancel := context.WithCancelCause(context.Background())
	defer func() {
		cancel(nil)
		log.Debug().Msg("user feed: connection closed")
	}()

	eventChan := runEventProducer(ctx, cancel, buildEventTopics(c))

	pumpStream(ctx, c.Request.Context(), eventChan,
		func(buf []byte) error {
			logWriteStringErr(io.WriteString(rw, "data: "))
			logWriteStringErr(rw.Write(buf))
			logWriteStringErr(io.WriteString(rw, "\n\n"))
			flusher.Flush()
			return nil
		},
		func() error {
			logWriteStringErr(io.WriteString(rw, ": ping\n\n"))
			flusher.Flush()
			return nil
		},
	)
}

// LogStreamSSE
//
//	@Summary	Stream logs of a pipeline step
//	@Router		/stream/sse/logs/{repo_id}/{pipeline}/{step_id} [get]
//	@Produce	plain
//	@Success	200
//	@Tags		Pipeline logs
//	@Param		repo_id		path	int	true	"the repository id"
//	@Param		pipeline	path	int	true	"the number of the pipeline"
//	@Param		step_id		path	int	true	"the step id"
func LogStreamSSE(c *gin.Context) {
	rw := c.Writer
	flusher, ok := rw.(http.Flusher)
	if !ok {
		c.String(http.StatusInternalServerError, "Streaming not supported")
		return
	}
	sseHeaders(c, "no-cache")

	logWriteStringErr(io.WriteString(rw, ": ping\n\n"))
	flusher.Flush()

	step, err := loadStepFromRequest(c)
	if err != nil {
		var sle *stepLoadError
		if errors.As(err, &sle) {
			log.Debug().Err(sle.cause).Msg("log stream: " + sle.sseMessage)
			logWriteStringErr(io.WriteString(rw, "event: error\ndata: "+sle.sseMessage+"\n\n"))
		}
		return
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	log.Debug().Msg("log stream: connection opened")
	defer func() {
		cancel(nil)
		log.Debug().Msg("log stream: connection closed")
	}()

	logChan, err := runLogProducer(ctx, cancel, step.ID)
	if err != nil {
		log.Error().Err(err).Msg("log stream: open failed")
		logWriteStringErr(io.WriteString(rw, "event: error\ndata: can't open stream\n\n"))
		return
	}

	// SSE supports resume via Last-Event-ID. We assign monotonic ids and skip
	// any payloads up to and including the id the client claims to have seen.
	id := 1
	last, _ := strconv.Atoi(c.Request.Header.Get("Last-Event-ID"))
	if last != 0 {
		log.Debug().Msgf("log stream: reconnect: last-event-id: %d", last)
	}

	pumpStream(ctx, c.Request.Context(), logChan,
		func(buf []byte) error {
			if id > last {
				logWriteStringErr(io.WriteString(rw, "id: "+strconv.Itoa(id)))
				logWriteStringErr(io.WriteString(rw, "\n"))
				logWriteStringErr(io.WriteString(rw, "data: "))
				logWriteStringErr(rw.Write(buf))
				logWriteStringErr(io.WriteString(rw, "\n\n"))
				flusher.Flush()
			}
			id++
			return nil
		},
		func() error {
			logWriteStringErr(io.WriteString(rw, ": ping\n\n"))
			flusher.Flush()
			return nil
		},
	)

	// After the loop: if the producer ended cleanly (tail done), emit the EOF
	// marker so the client knows to stop reconnecting. A client-side disconnect
	// (requestCtx cancel) leaves ctx with a non-Canceled cause and is silent.
	if cause := context.Cause(ctx); errors.Is(cause, context.Canceled) {
		log.Debug().Msg("log stream: eof")
		logWriteStringErr(io.WriteString(rw, "event: eof\ndata: eof\n\n"))
		flusher.Flush()
	}
}

// sseHeaders sets the response headers shared by every SSE handler.
func sseHeaders(c *gin.Context, cacheControl string) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", cacheControl)
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
}

func logWriteStringErr(_ int, err error) {
	if err != nil {
		log.Error().Err(err).Caller(1).Msg("fail to write string")
	}
}

// ============================================================================
// WebSocket handlers
// ============================================================================

// EventStreamWS
//
//	@Summary		Stream events like pipeline updates over WebSocket
//	@Description	WebSocket variant of /stream/events. Each text frame contains the
//	@Description	same JSON payload that the SSE endpoint emits in `data:` lines.
//	@Router			/stream/ws/events [get]
//	@Produce		json
//	@Success		101
//	@Tags			Events
func EventStreamWS(c *gin.Context) {
	conn, err := websocket.Accept(c.Writer, c.Request, wsAcceptOptions)
	if err != nil {
		log.Debug().Err(err).Msg("user feed: websocket accept failed")
		return
	}
	// CloseNow on defer guarantees the underlying TCP connection is released
	// even if the normal close handshake did not complete.
	defer conn.CloseNow()

	log.Debug().Msg("user feed: websocket connection opened")

	ctx, cancel := context.WithCancelCause(c.Request.Context())
	defer func() {
		cancel(nil)
		log.Debug().Msg("user feed: websocket connection closed")
	}()

	// Reader pump: we don't expect client messages, but we must keep reading so
	// that control frames (close, ping, pong) are handled by the library.
	// CloseRead achieves exactly that and cancels ctx when the peer disconnects.
	ctx = conn.CloseRead(ctx)

	eventChan := runEventProducer(ctx, cancel, buildEventTopics(c))

	pumpStream(ctx, c.Request.Context(), eventChan,
		func(buf []byte) error { return wsWrite(ctx, conn, buf) },
		func() error { return wsPing(ctx, conn) },
	)

	_ = conn.Close(websocket.StatusNormalClosure, "")
}

// LogStreamWS
//
//	@Summary	Stream logs of a pipeline step over WebSocket
//	@Router		/stream/ws/logs/{repo_id}/{pipeline}/{step_id} [get]
//	@Produce	json
//	@Success	101
//	@Tags		Pipeline logs
//	@Param		repo_id		path	int	true	"the repository id"
//	@Param		pipeline	path	int	true	"the number of the pipeline"
//	@Param		step_id		path	int	true	"the step id"
func LogStreamWS(c *gin.Context) {
	// Validate parameters BEFORE upgrading. Errors are returned as plain HTTP
	// responses, matching how a fetch() client expects auth/validation failures.
	step, err := loadStepFromRequest(c)
	if err != nil {
		var sle *stepLoadError
		if errors.As(err, &sle) {
			log.Debug().Err(sle.cause).Msg("log stream: " + sle.sseMessage)
			c.AbortWithStatus(sle.httpStatus)
			return
		}
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	conn, err := websocket.Accept(c.Writer, c.Request, wsAcceptOptions)
	if err != nil {
		log.Debug().Err(err).Msg("log stream: websocket accept failed")
		return
	}
	defer conn.CloseNow()

	log.Debug().Msg("log stream: websocket connection opened")

	ctx, cancel := context.WithCancelCause(c.Request.Context())
	defer func() {
		cancel(nil)
		log.Debug().Msg("log stream: websocket connection closed")
	}()

	ctx = conn.CloseRead(ctx)

	logChan, err := runLogProducer(ctx, cancel, step.ID)
	if err != nil {
		log.Error().Err(err).Msg("log stream: open failed")
		_ = conn.Close(websocket.StatusInternalError, "can't open stream")
		return
	}

	pumpStream(ctx, c.Request.Context(), logChan,
		func(buf []byte) error { return wsWrite(ctx, conn, buf) },
		func() error { return wsPing(ctx, conn) },
	)

	// Distinguish a clean EOF (tail completed) from an aborted client. On EOF
	// we close with reason "eof"; the client uses that to stop reconnecting.
	if cause := context.Cause(ctx); errors.Is(cause, context.Canceled) {
		log.Debug().Msg("log stream: eof")
		_ = conn.Close(websocket.StatusNormalClosure, "eof")
		return
	}
	_ = conn.Close(websocket.StatusNormalClosure, "")
}

// wsWrite writes a single text-frame payload, bounded by a deadline so a stuck
// client cannot block the producer indefinitely.
func wsWrite(ctx context.Context, conn *websocket.Conn, buf []byte) error {
	writeCtx, cancel := context.WithTimeout(ctx, idlePingTime)
	defer cancel()
	if err := conn.Write(writeCtx, websocket.MessageText, buf); err != nil {
		log.Debug().Err(err).Msg("websocket: write failed, closing")
		return err
	}
	return nil
}

// wsPing sends a control-frame ping and waits for the pong. coder/websocket's
// Ping is synchronous; the deadline keeps a non-responsive peer from stalling
// the loop.
func wsPing(ctx context.Context, conn *websocket.Conn) error {
	pingCtx, cancel := context.WithTimeout(ctx, idlePingTime)
	defer cancel()
	if err := conn.Ping(pingCtx); err != nil {
		log.Debug().Err(err).Msg("websocket: ping failed, closing")
		return err
	}
	return nil
}
