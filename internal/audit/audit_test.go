package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryWriter struct{ bytes.Buffer }

func (*memoryWriter) Close() error { return nil }

type heldWriter struct {
	started, release chan struct{}
	once             sync.Once
	memoryWriter
}

func (w *heldWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return w.memoryWriter.Write(p)
}

type badWriter struct{ short bool }

func (w badWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("SECRET_WRITE_ERROR")
}
func (badWriter) Close() error { return nil }
func finish(s *Sink) {
	ctx, o := s.Begin(context.Background(), "fetch", "request", "HTTP/1.1")
	o.Done(ctx, 200, "")
}
func closeSink(t *testing.T, s *Sink) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledHasNoWrapperOrFile(t *testing.T) {
	s, err := Open(Config{})
	if err != nil || s != nil {
		t.Fatalf("disabled=%v %v", s, err)
	}
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if s.HTTP("fetch", h) == nil {
		t.Fatal("nil handler")
	}
	ctx := context.Background()
	next, op := s.Begin(ctx, "fetch", "request", "")
	if next != ctx || op != nil {
		t.Fatal("disabled context changed")
	}
	if err = s.Close(nil); err != nil {
		t.Fatal(err)
	}
}

func TestCloseWaitsForStartedCompletion(t *testing.T) {
	w := new(memoryWriter)
	s := newSink(w, 4)
	ctx, op := s.Begin(context.Background(), "fetch", "request", "HTTP/1.1")
	closed := make(chan error, 1)
	go func() { closed <- s.Close(context.Background()) }()
	for {
		s.mu.Lock()
		closing := s.closing
		s.mu.Unlock()
		if closing {
			break
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-closed:
		t.Fatal("closed before operation completed")
	default:
	}
	Result(ctx, "HTTP/2.0", 200, "", "")
	op.Done(ctx, 200, "")
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if stats := s.Stats(); stats.Accepted != 1 || stats.Written != 1 || stats.DroppedClosed != 0 {
		t.Fatalf("close lost operation: %+v", stats)
	}
}

func TestGRPCNormalContextCleanupIsNotCancellation(t *testing.T) {
	w := new(memoryWriter)
	s := newSink(w, 4)
	ctx, cancel := context.WithCancel(context.Background())
	ctx, op := s.Begin(ctx, "grpc", "request", "HTTP/2.0")
	cancel()
	op.Done(ctx, 0, "OK")
	closeSink(t, s)
	var e Event
	json.Unmarshal(bytes.TrimSpace(w.Bytes()), &e)
	if e.ErrorCode != "" || e.RPCCode != "OK" {
		t.Fatalf("normal gRPC completion misclassified: %+v", e)
	}
}

func TestDeliberateHTTPRejectionSurvivesReadDeadlineCancellation(t *testing.T) {
	w := new(memoryWriter)
	s := newSink(w, 4)
	ctx, cancel := context.WithCancel(context.Background())
	ctx, op := s.Begin(ctx, "fetch", "request", "HTTP/1.1")
	cancel()
	op.Done(ctx, 503, "")
	closeSink(t, s)
	var e Event
	json.Unmarshal(bytes.TrimSpace(w.Bytes()), &e)
	if e.ErrorCode != "overloaded" {
		t.Fatalf("admission rejection misclassified: %+v", e)
	}
}

func TestCapacityAndBoundedDrain(t *testing.T) {
	w := &heldWriter{started: make(chan struct{}), release: make(chan struct{})}
	s := newSink(w, 2)
	finish(s)
	<-w.started
	finish(s)
	finish(s)
	finish(s)
	if stats := s.Stats(); stats.Accepted != 3 || stats.DroppedFull != 1 {
		t.Fatalf("N/N+1: %+v", stats)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain=%v", err)
	}
	finish(s)
	close(w.release)
	closeSink(t, s)
	stats := s.Stats()
	if stats.Written != 3 || stats.DroppedClosed != 1 || !stats.DrainExpired {
		t.Fatalf("drain stats=%+v", stats)
	}
}

func TestConcurrentCompletionAndClose(t *testing.T) {
	w := new(memoryWriter)
	s := newSink(w, 16)
	var wait sync.WaitGroup
	for i := 0; i < 100; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ctx, o := s.Begin(context.Background(), "grpc", "request", "HTTP/2.0")
			var twice sync.WaitGroup
			twice.Add(2)
			go func() { defer twice.Done(); o.Done(ctx, 0, "OK") }()
			go func() { defer twice.Done(); o.Done(ctx, 0, "OK") }()
			twice.Wait()
		}()
	}
	closeSink(t, s)
	wait.Wait()
	closeSink(t, s)
	stats := s.Stats()
	if stats.Accepted+stats.DroppedFull+stats.DroppedClosed != 100 || stats.Written != stats.Accepted {
		t.Fatalf("counts=%+v", stats)
	}
	seen := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(w.Bytes()), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		if seen[e.RequestID] {
			t.Fatal("duplicate completion")
		}
		seen[e.RequestID] = true
	}
}

func TestFixedFieldsAndNoRequestSecrets(t *testing.T) {
	w := new(memoryWriter)
	s := newSink(w, 8)
	h := s.HTTP("fetch", http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		Result(r.Context(), "HTTP/2.0", 200, "SECRET_ERROR", "SECRET_PHASE")
		out.Header().Add("Set-Cookie", "SECRET_RESPONSE_COOKIE")
		out.Write([]byte("SECRET_RESPONSE_BODY"))
	}))
	req := httptest.NewRequest("POST", "http://SECRET_USER:SECRET_PASSWORD@example.test/SECRET_PATH?token=SECRET_QUERY", strings.NewReader("SECRET_BODY"))
	req.Header.Set("Authorization", "SECRET_AUTH")
	req.Header.Set("Cookie", "SECRET_COOKIE")
	req.Header.Set("X-Request-ID", "SECRET_ID")
	h.ServeHTTP(httptest.NewRecorder(), req)
	closeSink(t, s)
	if strings.Contains(w.String(), "SECRET") {
		t.Fatalf("secret leaked: %s", w.String())
	}
	var e Event
	if err := json.Unmarshal(bytes.TrimSpace(w.Bytes()), &e); err != nil {
		t.Fatal(err)
	}
	if len(e.RequestID) != 32 || e.Schema != 1 || e.UpstreamProtocol != "HTTP/2.0" || e.DownstreamProtocol != "HTTP/1.1" || e.ErrorCode != "internal_error" || e.DurationUS < 0 {
		t.Fatalf("event=%+v", e)
	}
}

func TestCancellationAndAbortDoNotBecomeSuccess(t *testing.T) {
	w := new(memoryWriter)
	s := newSink(w, 8)
	ctx, cancel := context.WithCancel(context.Background())
	ctx, o := s.Begin(ctx, "mitm", "request", "HTTP/1.1")
	cancel()
	o.Done(ctx, 200, "")
	h := s.HTTP("mitm", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("abort swallowed")
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}()
	closeSink(t, s)
	lines := bytes.Split(bytes.TrimSpace(w.Bytes()), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatal(w.String())
	}
	for i, want := range []string{"cancelled", "read_error"} {
		var e Event
		json.Unmarshal(lines[i], &e)
		if e.ErrorCode != want {
			t.Fatalf("event=%+v", e)
		}
	}
}

func TestWriteFailuresAreStickyAndSanitized(t *testing.T) {
	for _, short := range []bool{false, true} {
		s := newSink(badWriter{short}, 8)
		finish(s)
		if err := s.Close(context.Background()); err != ErrWrite {
			t.Fatalf("write error=%v", err)
		}
		if s.Stats().DroppedWrite != 1 || s.Stats().Written != 0 {
			t.Fatalf("stats=%+v", s.Stats())
		}
	}
}

func TestConfigurationAndFileAppend(t *testing.T) {
	for _, c := range []Config{{Queue: -1}, {Queue: 65537}, {DrainTimeout: -1}, {DrainTimeout: time.Minute + 1}} {
		if _, err := Open(c); err == nil {
			t.Fatalf("invalid config %+v", c)
		}
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for i := 0; i < 2; i++ {
		s, err := Open(Config{File: path, Queue: 4})
		if err != nil {
			t.Fatal(err)
		}
		finish(s)
		closeSink(t, s)
	}
	data, err := os.ReadFile(path)
	if err != nil || len(bytes.Split(bytes.TrimSpace(data), []byte{'\n'})) != 2 {
		t.Fatalf("append: %q %v", data, err)
	}
	if _, err = Open(Config{File: t.TempDir()}); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err = Open(Config{File: filepath.Join(t.TempDir(), "missing", "audit")}); err == nil {
		t.Fatal("missing parent accepted")
	}
}

func TestHTTPWrapperPreservesWireTrailersAndDeadlineController(t *testing.T) {
	w := new(memoryWriter)
	s := newSink(w, 8)
	server := httptest.NewServer(s.HTTP("mitm", http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(out).SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Error(err)
		}
		out.Header().Set("Trailer", "X-Final")
		out.Header().Add("X-Multi", "one")
		out.Header().Add("X-Multi", "two")
		out.Write([]byte{0, 255})
		out.(http.Flusher).Flush()
		out.Header().Set("X-Final", "done")
	})))
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	server.Close()
	closeSink(t, s)
	if err != nil || !bytes.Equal(body, []byte{0, 255}) || len(resp.Header.Values("X-Multi")) != 2 || resp.Trailer.Get("X-Final") != "done" {
		t.Fatalf("wire body=%x header=%v trailer=%v err=%v", body, resp.Header, resp.Trailer, err)
	}
}
