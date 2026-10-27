// Package audit emits bounded, allowlisted completion events. It never accepts
// request URLs, headers, bodies, user IDs or raw error messages.
package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	File         string
	Queue        int
	DrainTimeout time.Duration
}

func (c *Config) BindFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.File, "audit-file", "", "Private JSONL audit file; empty disables auditing")
	flags.IntVar(&c.Queue, "audit-queue", 1024, "Pending audit events (1..65536); full queues drop new events")
	flags.DurationVar(&c.DrainTimeout, "audit-drain-timeout", 5*time.Second, "Audit shutdown drain budget (0 selects 5s, maximum 1m)")
}

func (c Config) validate() error {
	if c.Queue < 0 || c.Queue > 65536 {
		return errors.New("audit-queue must be 1..65536 (0 selects 1024)")
	}
	if c.DrainTimeout < 0 || c.DrainTimeout > time.Minute {
		return errors.New("audit-drain-timeout must be 0..1m")
	}
	return nil
}

type Event struct {
	Schema             int       `json:"schema_version"`
	RequestID          string    `json:"request_id"`
	ParentID           string    `json:"parent_id,omitempty"`
	Time               time.Time `json:"time"`
	Entry              string    `json:"entry"`
	Kind               string    `json:"kind"`
	DownstreamProtocol string    `json:"downstream_protocol,omitempty"`
	UpstreamProtocol   string    `json:"upstream_protocol,omitempty"`
	DownstreamStatus   int       `json:"downstream_status,omitempty"`
	UpstreamStatus     int       `json:"upstream_status,omitempty"`
	RPCCode            string    `json:"rpc_code,omitempty"`
	DurationUS         int64     `json:"duration_us"`
	ErrorCode          string    `json:"error_code,omitempty"`
	TimeoutPhase       string    `json:"timeout_phase,omitempty"`
}

type Stats struct {
	Accepted      uint64 `json:"accepted"`
	Written       uint64 `json:"written"`
	DroppedFull   uint64 `json:"dropped_full"`
	DroppedClosed uint64 `json:"dropped_closed"`
	DroppedWrite  uint64 `json:"dropped_write"`
	DrainExpired  bool   `json:"drain_expired"`
}

type Sink struct {
	closing                                  bool
	active                                   int
	idle                                     chan struct{}
	mu                                       sync.Mutex
	queue                                    chan Event
	done                                     chan struct{}
	closed, failed                           bool
	accepted, written, full, late, writeDrop atomic.Uint64
	expired                                  atomic.Bool
}

var ErrWrite = errors.New("audit output failed")

func Open(c Config) (*Sink, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if c.File == "" {
		return nil, nil
	}
	f, err := os.OpenFile(c.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("audit-file must be a regular file")
	}
	capacity := c.Queue
	if capacity == 0 {
		capacity = 1024
	}
	return newSink(f, capacity), nil
}

func newSink(writer io.WriteCloser, capacity int) *Sink {
	s := &Sink{queue: make(chan Event, capacity), done: make(chan struct{}), idle: make(chan struct{})}
	go func() {
		defer close(s.done)
		for event := range s.queue {
			s.mu.Lock()
			failed := s.failed
			s.mu.Unlock()
			if failed {
				s.writeDrop.Add(1)
				continue
			}
			data, err := json.Marshal(event)
			if err == nil {
				data = append(data, '\n')
				var n int
				n, err = writer.Write(data)
				if n != len(data) && err == nil {
					err = io.ErrShortWrite
				}
			}
			if err != nil {
				s.mu.Lock()
				s.failed = true
				s.mu.Unlock()
				s.writeDrop.Add(1)
			} else {
				s.written.Add(1)
			}
		}
		if err := writer.Close(); err != nil {
			s.mu.Lock()
			s.failed = true
			s.mu.Unlock()
		}
	}()
	return s
}

func (s *Sink) submit(event Event) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.late.Add(1)
		return
	}
	if s.failed {
		s.writeDrop.Add(1)
		return
	}
	select {
	case s.queue <- event:
		s.accepted.Add(1)
	default:
		s.full.Add(1)
	}
}

// Close stops producers and drains accepted events. Only the worker owns the
// writer. A blocked OS write cannot be portably interrupted; the caller's
// deadline bounds Close, not the OS operation, and is reported as a failure.
func (s *Sink) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("nil audit close context")
	}
	s.mu.Lock()
	if !s.closing {
		s.closing = true
		if s.active == 0 {
			close(s.idle)
		}
	}
	s.mu.Unlock()
	select {
	case <-s.idle:
	case <-ctx.Done():
		s.expired.Store(true)
		s.seal()
		return ctx.Err()
	}
	s.seal()
	select {
	case <-s.done:
		return s.outputError()
	default:
	}
	select {
	case <-s.done:
		return s.outputError()
	case <-ctx.Done():
		s.expired.Store(true)
		return ctx.Err()
	}
}
func (s *Sink) seal() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()
}
func (s *Sink) outputError() error {
	s.mu.Lock()
	failed := s.failed
	s.mu.Unlock()
	if failed {
		return ErrWrite
	}
	return nil
}
func (s *Sink) end() {
	s.mu.Lock()
	s.active--
	if s.closing && s.active == 0 {
		close(s.idle)
	}
	s.mu.Unlock()
}

func (s *Sink) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	return Stats{s.accepted.Load(), s.written.Load(), s.full.Load(), s.late.Load(), s.writeDrop.Load(), s.expired.Load()}
}

// Run is the CLI owner: all startup/serve errors return through drain before
// main exits. Disabled mode opens no file and starts no worker.
func Run(c Config, serve func(*Sink) error) error {
	s, err := Open(c)
	if err != nil {
		return err
	}
	serveErr := serve(s)
	budget := c.DrainTimeout
	if budget == 0 {
		budget = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	err = s.Close(ctx)
	if s != nil {
		_ = json.NewEncoder(os.Stderr).Encode(struct {
			Stats Stats `json:"audit_stats"`
		}{s.Stats()})
	}
	return errors.Join(serveErr, err)
}

type contextKey struct{}
type Operation struct {
	sink  *Sink
	start time.Time
	mu    sync.Mutex
	once  sync.Once
	event Event
}

func (s *Sink) Begin(ctx context.Context, entry, kind, protocol string) (context.Context, *Operation) {
	if s == nil {
		return ctx, nil
	}
	s.mu.Lock()
	if s.closing {
		s.late.Add(1)
		s.mu.Unlock()
		return context.WithValue(ctx, contextKey{}, (*Operation)(nil)), nil
	}
	s.active++
	s.mu.Unlock()
	var id [16]byte
	_, _ = rand.Read(id[:])
	e := Event{Schema: 1, RequestID: hex.EncodeToString(id[:]), Time: time.Now().UTC(), Entry: oneOf(entry, "fetch", "jsonrpc", "grpc", "mitm"), Kind: oneOf(kind, "request", "connect", "tcp_rejected"), DownstreamProtocol: proto(protocol)}
	if parent, _ := ctx.Value(contextKey{}).(*Operation); parent != nil {
		e.ParentID = parent.event.RequestID
	}
	o := &Operation{sink: s, start: time.Now(), event: e}
	return context.WithValue(ctx, contextKey{}, o), o
}

func Result(ctx context.Context, protocol string, status int, code, phase string) {
	o, _ := ctx.Value(contextKey{}).(*Operation)
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if protocol != "" {
		o.event.UpstreamProtocol = proto(protocol)
	}
	if status >= 100 && status <= 599 {
		o.event.UpstreamStatus = status
	}
	if code != "" {
		o.event.ErrorCode = errorCode(code)
		o.event.TimeoutPhase = ""
		if o.event.ErrorCode == "timeout" {
			o.event.TimeoutPhase = oneOf(phase, "total", "connect", "headers", "read", "write")
		}
	}
}

func Downstream(ctx context.Context, status int) {
	o, _ := ctx.Value(contextKey{}).(*Operation)
	if o == nil {
		return
	}
	if status >= 100 && status <= 599 {
		o.mu.Lock()
		o.event.DownstreamStatus = status
		o.mu.Unlock()
	}
}

func Fail(ctx context.Context, code, phase string) {
	o, _ := ctx.Value(contextKey{}).(*Operation)
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.event.ErrorCode == "" {
		o.event.ErrorCode = errorCode(code)
		o.event.TimeoutPhase = ""
		if o.event.ErrorCode == "timeout" {
			o.event.TimeoutPhase = oneOf(phase, "total", "connect", "headers", "read", "write")
		}
	}
}

func RPCStatus(ctx context.Context, code string) {
	o, _ := ctx.Value(contextKey{}).(*Operation)
	if o == nil {
		return
	}
	o.mu.Lock()
	o.event.RPCCode = oneOf(code, "OK", "Canceled", "Unknown", "InvalidArgument", "DeadlineExceeded", "NotFound", "AlreadyExists", "PermissionDenied", "ResourceExhausted", "FailedPrecondition", "Aborted", "OutOfRange", "Unimplemented", "Internal", "Unavailable", "DataLoss", "Unauthenticated")
	o.mu.Unlock()
}

func (o *Operation) Done(ctx context.Context, status int, rpcCode string) {
	if o == nil {
		return
	}
	o.once.Do(func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		e := o.event
		if status >= 100 && status <= 599 {
			e.DownstreamStatus = status
		}
		if rpcCode != "" {
			e.RPCCode = oneOf(rpcCode, "OK", "Canceled", "Unknown", "InvalidArgument", "DeadlineExceeded", "NotFound", "AlreadyExists", "PermissionDenied", "ResourceExhausted", "FailedPrecondition", "Aborted", "OutOfRange", "Unimplemented", "Internal", "Unavailable", "DataLoss", "Unauthenticated")
		}
		if e.ErrorCode == "" {
			switch {
			case status == 413:
				e.ErrorCode = "request_too_large"
			case status == 503:
				e.ErrorCode = "overloaded"
			case status == 401 || status == 407:
				e.ErrorCode = "unauthorized"
			case status == 403:
				e.ErrorCode = "forbidden"
			case status >= 500:
				e.ErrorCode = "request_error"
			case status >= 400:
				e.ErrorCode = "invalid_request"
			}
		}
		if e.ErrorCode == "" || e.ErrorCode == "request_error" || e.ErrorCode == "read_error" {
			cause := ctx.Err()
			if e.Entry == "grpc" {
				cause = nil
				if e.RPCCode == "Canceled" {
					cause = context.Canceled
				}
				if e.RPCCode == "DeadlineExceeded" {
					cause = context.DeadlineExceeded
				}
			}
			if cause != nil {
				e.ErrorCode, e.TimeoutPhase = Error(cause, e.ErrorCode)
			}
		}
		if e.Entry == "grpc" && e.RPCCode == "" {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				e.RPCCode = "DeadlineExceeded"
			} else if ctx.Err() != nil {
				e.RPCCode = "Canceled"
			}
		}
		e.DurationUS = time.Since(o.start).Microseconds()
		if e.DurationUS < 0 {
			e.DurationUS = 0
		}
		o.sink.submit(e)
		o.sink.end()
	})
}

func (s *Sink) Reject(entry string) {
	ctx, o := s.Begin(context.Background(), entry, "tcp_rejected", "")
	Result(ctx, "", 0, "overloaded", "")
	o.Done(ctx, 0, "")
}

func Error(err error, fallback string) (string, string) {
	var denied interface{ AddressPolicyReason() string }
	var timeout net.Error
	switch {
	case errors.As(err, &denied):
		return "address_denied", ""
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", "total"
	case errors.Is(err, context.Canceled):
		return "cancelled", ""
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timeout", "total"
	default:
		return errorCode(fallback), ""
	}
}

func errorCode(s string) string {
	if v := oneOf(s, "invalid_request", "request_error", "read_error", "decode_error", "timeout", "cancelled", "address_denied", "overloaded", "request_too_large", "response_too_large", "unauthorized", "forbidden", "internal_error", "transport_error", "traffic_limited", "not_found"); v != "" {
		return v
	}
	return "internal_error"
}
func proto(s string) string { return oneOf(s, "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0") }
func oneOf(s string, allowed ...string) string {
	for _, v := range allowed {
		if s == v {
			return s
		}
	}
	return ""
}
