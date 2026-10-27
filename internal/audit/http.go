package audit

import (
	"bufio"
	"net"
	"net/http"
)

func (s *Sink) HTTP(entry string, next http.Handler) http.Handler {
	if s == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind := "request"
		if r.Method == http.MethodConnect {
			kind = "connect"
		}
		ctx, op := s.Begin(r.Context(), entry, kind, r.Proto)
		out := &statusWriter{ResponseWriter: w}
		defer func() {
			failure := recover()
			if out.code != "" {
				Fail(ctx, out.code, out.phase)
			}
			if failure != nil {
				code := "internal_error"
				if failure == http.ErrAbortHandler {
					code = "read_error"
				}
				Fail(ctx, code, "")
			}
			status := out.status
			if status == 0 && failure == nil && !out.hijacked {
				status = 200
			}
			op.Done(ctx, status, "")
			if failure != nil {
				panic(failure)
			}
		}()
		next.ServeHTTP(out, r.WithContext(ctx))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	hijacked    bool
	code, phase string
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *statusWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != 101 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(p)
	if err != nil {
		w.code, w.phase = Error(err, "transport_error")
	}
	return n, err
}
func (w *statusWriter) Flush() { _ = w.FlushError() }
func (w *statusWriter) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if err != nil {
		w.code, w.phase = Error(err, "transport_error")
	}
	return err
}
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffer, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.hijacked = true
	}
	return conn, buffer, err
}

func (w *statusWriter) CloseNotify() <-chan bool {
	return w.ResponseWriter.(http.CloseNotifier).CloseNotify()
}
func (w *statusWriter) Push(target string, options *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, options)
	}
	return http.ErrNotSupported
}
