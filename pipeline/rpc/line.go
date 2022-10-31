package rpc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/woodpecker-ci/woodpecker/pipeline/shared"
)

// Identifies the type of line in the logs.
const (
	LineStdout int = iota
	LineStderr
	LineExitCode
	LineMetadata
	LineProgress
)

// Line is a line of console output.
type Line struct {
	Step string `json:"step,omitempty"`
	Time int64  `json:"time,omitempty"`
	Type int    `json:"type,omitempty"`
	Pos  int    `json:"pos,omitempty"`
	Out  string `json:"out,omitempty"`
}

func (l *Line) String() string {
	switch l.Type {
	case LineExitCode:
		return fmt.Sprintf("[%s] exit code %s", l.Step, l.Out)
	default:
		return fmt.Sprintf("[%s:L%v:%vs] %s", l.Step, l.Pos, l.Time, l.Out)
	}
}

// LineWriter sends logs to the client.
type LineWriter struct {
	peer  Peer
	id    string
	name  string
	num   int
	now   time.Time
	rep   *strings.Replacer
	lines []*Line
}

// NewLineWriter returns a new line reader.
func NewLineWriter(peer Peer, id, name string, secret ...string) *LineWriter {
	return &LineWriter{
		peer:  peer,
		id:    id,
		name:  name,
		now:   time.Now().UTC(),
		rep:   shared.NewSecretsReplacer(secret),
		lines: nil,
	}
}

func (w *LineWriter) Write(p []byte) (n int, err error) {
	out := string(p)
	if w.rep != nil {
		out = w.rep.Replace(out)
	}
	log.Trace().Str("name", w.name).Str("ID", w.id).Msgf("grpc write line: %s", out)

	line := &Line{
		Out:  out,
		Step: w.name,
		Pos:  w.num,
		Time: int64(time.Since(w.now).Seconds()),
		Type: LineStdout,
	}
	if err := w.peer.Log(context.Background(), w.id, line); err != nil {
		log.Error().Err(err).Msgf("fail to write pipeline log to peer '%s'", w.id)
	}
	w.num++

	// for _, part := range bytes.Split(p, []byte{'\n'}) {
	// 	line := &Line{
	// 		Out:  string(part),
	// 		Step: w.name,
	// 		Pos:  w.num,
	// 		Time: int64(time.Since(w.now).Seconds()),
	// 		Type: LineStdout,
	// 	}
	// 	w.peer.Log(context.Background(), w.id, line)
	// 	w.num++
	// }
	w.lines = append(w.lines, line)
	return len(p), nil
}

// Lines returns the line history
func (w *LineWriter) Lines() []*Line {
	return w.lines
}

// Clear clears the line history
func (w *LineWriter) Clear() {
	w.lines = w.lines[:0]
}
