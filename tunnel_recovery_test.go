package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
)

type recoveryTransport struct {
	calls, idleCloses int
	reused            bool
	err               error
	response          *http.Response
	seen              []*http.Request
}

func (r *recoveryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls++
	r.seen = append(r.seen, req)
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Reused: r.reused})
	}
	return r.response, r.err
}
func (r *recoveryTransport) CloseIdleConnections() { r.idleCloses++ }

func TestDefaultTunnelRecoveryIsBoundedAndSafe(t *testing.T) {
	for _, name := range []string{"get", "head", "post", "get-body", "get-empty-body", "new-connection", "cancelled", "other-error", "response", "trailers"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/", nil)
			if err != nil {
				t.Fatal(err)
			}
			transport := &recoveryTransport{reused: true, err: fmt.Errorf("wrapped: %w", io.ErrUnexpectedEOF)}
			want := 1
			switch name {
			case "get":
				want = 2
			case "head":
				request.Method = http.MethodHead
				transport.err = io.EOF
				want = 2
			case "post":
				request.Method = http.MethodPost
			case "get-body":
				request.Body = io.NopCloser(strings.NewReader("payload"))
			case "get-empty-body":
				request.Body = io.NopCloser(strings.NewReader(""))
			case "new-connection":
				transport.reused = false
			case "cancelled":
				cancel()
			case "other-error":
				transport.err = context.DeadlineExceeded
			case "response":
				transport.response = &http.Response{StatusCode: 502, Body: http.NoBody}
			case "trailers":
				request.Trailer = http.Header{"X-End": []string{"value"}}
			}
			response, gotErr := roundTripDefaultTunnel(transport, request)
			if gotErr != transport.err || response != transport.response || transport.calls != want || transport.idleCloses != want-1 {
				t.Fatalf("calls=%d idleCloses=%d response=%v err=%v", transport.calls, transport.idleCloses, response, gotErr)
			}
			for _, seen := range transport.seen {
				if seen.Context().Done() != ctx.Done() || seen.URL != request.URL || seen.Body != request.Body {
					t.Fatal("recovery changed request ownership or cancellation")
				}
			}
		})
	}
}
