package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type trailerOnEOF struct {
	io.Reader
	trailer http.Header
}

func (b *trailerOnEOF) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		b.trailer["X-Final"] = []string{"one", "two"}
	}
	return n, err
}
func (*trailerOnEOF) Close() error { return nil }

func TestHTTP2BridgeResponseFramingAndTrailers(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	proxy.SetDeadline(time.Now().Add(2 * time.Second))
	trailers := http.Header{"X-Final": nil}
	response := &http.Response{StatusCode: 200, Proto: "HTTP/2.0", ProtoMajor: 2, ContentLength: -1,
		Header:  http.Header{"X-Repeat": {"first", "second"}, "Set-Cookie": {"a=1; Path=/", "b=2; Expires=Wed, 21 Oct 2037 07:28:00 GMT"}},
		Trailer: trailers, Body: &trailerOnEOF{Reader: strings.NewReader("binary\x00body"), trailer: trailers}, Request: &http.Request{Method: "GET"},
	}
	done := make(chan error, 1)
	go func() {
		p := new(MITMProxy)
		if err := p.writeHTTP1Response(proxy, response); err != nil {
			done <- err
			return
		}
		done <- p.writeHTTP1Response(proxy, &http.Response{StatusCode: 204, Header: make(http.Header), Body: http.NoBody, Request: &http.Request{Method: "GET"}})
	}()
	reader := bufio.NewReader(client)
	first, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(first.Body)
	first.Body.Close()
	if err != nil || string(data) != "binary\x00body" {
		t.Fatalf("first body=%q err=%v", data, err)
	}
	if !reflect.DeepEqual(first.Header.Values("X-Repeat"), []string{"first", "second"}) || len(first.Header.Values("Set-Cookie")) != 2 {
		t.Fatalf("lost headers: %v", first.Header)
	}
	if !reflect.DeepEqual(first.Trailer.Values("X-Final"), []string{"one", "two"}) {
		t.Fatalf("lost trailers: %v", first.Trailer)
	}
	second, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	second.Body.Close()
	if second.StatusCode != 204 {
		t.Fatalf("second status=%d", second.StatusCode)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPlainProxyPreservesRepeatedResponseHeadersAndTrailers(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1; Path=/")
		w.Header().Add("Set-Cookie", "b=2; Path=/")
		w.Header().Add("X-Repeat", "first")
		w.Header().Add("X-Repeat", "second")
		w.Header().Set("Trailer", "X-Final")
		io.WriteString(w, "ok")
		w.Header().Set("X-Final", "complete")
	}))
	defer target.Close()
	p := newTemporaryProxy(t)
	request := httptest.NewRequest("GET", target.URL, nil)
	recorder := httptest.NewRecorder()
	p.handler().ServeHTTP(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "ok" {
		t.Fatalf("body=%q err=%v", data, err)
	}
	if len(response.Header.Values("Set-Cookie")) != 2 || !reflect.DeepEqual(response.Header.Values("X-Repeat"), []string{"first", "second"}) {
		t.Fatalf("lost headers: %v", response.Header)
	}
	if response.Trailer.Get("X-Final") != "complete" {
		t.Fatalf("lost trailer: %v", response.Trailer)
	}
}
