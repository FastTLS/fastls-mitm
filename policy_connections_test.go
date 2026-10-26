package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPolicyLeasedConnectionReleasesOnce(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	var released atomic.Int32
	conn := &policyLeasedConn{Conn: left, release: func() { released.Add(1) }}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); conn.Close() }()
	}
	wg.Wait()
	if released.Load() != 1 {
		t.Fatal("connection permit released more than once")
	}
}

func TestPolicyTrafficExactReadAndWriteBudgets(t *testing.T) {
	for _, reading := range []bool{false, true} {
		left, right := net.Pipe()
		left.SetDeadline(time.Now().Add(time.Second))
		right.SetDeadline(time.Now().Add(time.Second))
		conn := newPolicyTrafficConn(left, 4, 4)
		if n, err := conn.Read(nil); n != 0 || err != nil {
			t.Fatal(n, err)
		}
		if n, err := conn.Write(nil); n != 0 || err != nil {
			t.Fatal(n, err)
		}
		done := make(chan error, 1)
		if reading {
			go func() { _, err := right.Write([]byte("12345")); done <- err }()
			data, err := io.ReadAll(conn)
			if string(data) != "1234" || !errors.Is(err, errPolicyTrafficLimit) {
				t.Fatalf("read budget data=%q err=%v", data, err)
			}
			<-done
		} else {
			go func() {
				data, err := io.ReadAll(right)
				if err == nil && !bytes.Equal(data, []byte("1234")) {
					err = errors.New("wrong emitted bytes")
				}
				done <- err
			}()
			if n, err := conn.Write([]byte("12")); n != 2 || err != nil {
				t.Fatal(n, err)
			}
			if n, err := conn.Write([]byte("345")); n != 2 || !errors.Is(err, errPolicyTrafficLimit) {
				t.Fatal(n, err)
			}
			if n, err := conn.Write([]byte("x")); n != 0 || !errors.Is(err, errPolicyTrafficLimit) {
				t.Fatal("exhausted budget emitted data", n, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
		conn.Close()
		right.Close()
	}
}

func TestPolicyTrafficBlockedReadDoesNotConsumeWriteBudget(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	left.SetDeadline(time.Now().Add(time.Second))
	right.SetDeadline(time.Now().Add(time.Second))
	conn := newPolicyTrafficConn(left, 8, 8)
	readDone := make(chan error, 1)
	go func() { data := make([]byte, 1); _, err := conn.Read(data); readDone <- err }()
	writeDone := make(chan error, 1)
	go func() {
		data := make([]byte, 1)
		_, err := io.ReadFull(right, data)
		if err == nil {
			_, err = right.Write([]byte("r"))
		}
		writeDone <- err
	}()
	if _, err := conn.Write([]byte("w")); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
}

type policyShortWriter struct{ net.Conn }

func (c policyShortWriter) Write(p []byte) (int, error) { return min(2, len(p)), nil }

func TestPolicyTrafficCountsActualShortWriteBytes(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := newPolicyTrafficConn(policyShortWriter{left}, 0, 4)
	if n, err := conn.Write([]byte("123")); n != 2 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(n, err)
	}
	if n, err := conn.Write([]byte("45")); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if conn.writeRemaining != 0 {
		t.Fatal("short write consumed untransmitted bytes")
	}
}

type policyMemoryConn struct {
	net.Conn
	input  *bytes.Reader
	output bytes.Buffer
	closed bool
}

func (c *policyMemoryConn) Read(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.input.Read(p)
}
func (c *policyMemoryConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.output.Write(p)
}
func (c *policyMemoryConn) Close() error { c.closed = true; return nil }

func FuzzPolicyTrafficBudget(f *testing.F) {
	f.Add([]byte("12345"), uint16(4))
	f.Add([]byte("1234"), uint16(4))
	f.Add([]byte("unlimited"), uint16(0))
	f.Fuzz(func(t *testing.T, data []byte, budget uint16) {
		if len(data) > 8192 {
			t.Skip()
		}
		want := len(data)
		if budget > 0 && want > int(budget) {
			want = int(budget)
		}
		for _, reading := range []bool{true, false} {
			memory := &policyMemoryConn{input: bytes.NewReader(data)}
			conn := newPolicyTrafficConn(memory, int64(budget), int64(budget))
			if reading {
				got, _ := io.ReadAll(conn)
				if !bytes.Equal(got, data[:want]) {
					t.Fatal("read exceeded or corrupted quota")
				}
			} else {
				n, _ := conn.Write(data)
				if n != want || !bytes.Equal(memory.output.Bytes(), data[:want]) {
					t.Fatal("write exceeded or corrupted quota")
				}
			}
			if budget > 0 && len(data) >= int(budget) && !memory.closed {
				t.Fatal("exhausted budget did not close connection")
			}
		}
	})
}
