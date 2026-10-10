// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package store

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMemoryTTLAndBound(t *testing.T) {
	now := time.Unix(0, 0)
	m := NewMemory(3)
	m.now = func() time.Time { return now }
	ctx := context.Background()
	ok, _ := m.SetNX(ctx, "a", []byte("1"), time.Second)
	again, _ := m.SetNX(ctx, "a", []byte("2"), time.Second)
	if !ok || again {
		t.Fatal("SetNX semantics")
	}
	now = now.Add(2 * time.Second)
	if _, err := m.Get(ctx, "a"); err != ErrNotFound {
		t.Fatal("expired entry must be gone")
	}
	for _, k := range []string{"b", "c", "d", "e"} {
		m.Set(ctx, k, []byte(k), time.Minute)
	}
	if m.Len() > 3 {
		t.Fatalf("bound violated: %d", m.Len())
	}
	if _, err := m.Get(ctx, "e"); err != nil {
		t.Fatal("newest must survive eviction")
	}
	n1, _ := m.Incr(ctx, "rl", time.Minute)
	n2, _ := m.Incr(ctx, "rl", time.Minute)
	if n1 != 1 || n2 != 2 {
		t.Fatalf("incr: %d %d", n1, n2)
	}
}

// A tiny RESP server implementing just enough of Redis to test the client.
func fakeRedis(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	data := map[string]string{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					v, err := readReply(br)
					if err != nil {
						return
					}
					args := v.([]any)
					cmd := strings.ToUpper(string(args[0].([]byte)))
					mu.Lock()
					switch cmd {
					case "PING":
						c.Write([]byte("+PONG\r\n"))
					case "GET":
						if s, ok := data[string(args[1].([]byte))]; ok {
							c.Write([]byte("$" + itoa(len(s)) + "\r\n" + s + "\r\n"))
						} else {
							c.Write([]byte("$-1\r\n"))
						}
					case "SET":
						k, val := string(args[1].([]byte)), string(args[2].([]byte))
						nx := false
						for _, a := range args[3:] {
							if strings.ToUpper(string(a.([]byte))) == "NX" {
								nx = true
							}
						}
						if _, exists := data[k]; nx && exists {
							c.Write([]byte("$-1\r\n"))
						} else {
							data[k] = val
							c.Write([]byte("+OK\r\n"))
						}
					case "INCR":
						k := string(args[1].([]byte))
						n := 0
						if s, ok := data[k]; ok {
							n = atoi(s)
						}
						n++
						data[k] = itoa(n)
						c.Write([]byte(":" + itoa(n) + "\r\n"))
					case "PEXPIRE":
						c.Write([]byte(":1\r\n"))
					default:
						c.Write([]byte("-ERR unknown\r\n"))
					}
					mu.Unlock()
				}
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func itoa(n int) string { return strconv.Itoa(n) }
func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

func TestRedisClient(t *testing.T) {
	addr := fakeRedis(t)
	r := NewRedis(addr, "", 2)
	ctx := context.Background()
	if err := r.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	ok, err := r.SetNX(ctx, "k", []byte("v1"), time.Minute)
	if err != nil || !ok {
		t.Fatalf("setnx: %v %v", ok, err)
	}
	ok, _ = r.SetNX(ctx, "k", []byte("v2"), time.Minute)
	if ok {
		t.Fatal("second setnx must fail")
	}
	v, err := r.Get(ctx, "k")
	if err != nil || string(v) != "v1" {
		t.Fatalf("get: %q %v", v, err)
	}
	if _, err := r.Get(ctx, "missing"); err != ErrNotFound {
		t.Fatal("missing key")
	}
	n, _ := r.Incr(ctx, "c", time.Minute)
	n2, _ := r.Incr(ctx, "c", time.Minute)
	if n != 1 || n2 != 2 {
		t.Fatalf("incr %d %d", n, n2)
	}
}
