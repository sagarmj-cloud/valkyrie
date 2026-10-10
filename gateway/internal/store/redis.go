// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package store

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Redis is a minimal RESP2 client: a pooled set of connections and the five
// commands the gateway needs. It deliberately implements no more than that;
// a full client is a dependency, and the gateway's whole value is a small,
// auditable surface.
type Redis struct {
	addr     string
	password string
	pool     chan net.Conn
	dialMu   sync.Mutex
	timeout  time.Duration
	Prefix   string
}

func NewRedis(addr, password string, poolSize int) *Redis {
	if poolSize <= 0 {
		poolSize = 8
	}
	return &Redis{addr: addr, password: password, pool: make(chan net.Conn, poolSize), timeout: 2 * time.Second, Prefix: "valkyrie:"}
}

func (r *Redis) conn(ctx context.Context) (net.Conn, error) {
	select {
	case c := <-r.pool:
		return c, nil
	default:
	}
	d := net.Dialer{Timeout: r.timeout}
	c, err := d.DialContext(ctx, "tcp", r.addr)
	if err != nil {
		return nil, err
	}
	if r.password != "" {
		if _, err := r.do(ctx, c, "AUTH", r.password); err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}

func (r *Redis) release(c net.Conn, broken bool) {
	if broken {
		c.Close()
		return
	}
	select {
	case r.pool <- c:
	default:
		c.Close()
	}
}

// do writes one command as a RESP array and reads one reply.
func (r *Redis) do(ctx context.Context, c net.Conn, args ...string) (any, error) {
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	} else {
		c.SetDeadline(time.Now().Add(r.timeout))
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&sb, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := io.WriteString(c, sb.String()); err != nil {
		return nil, err
	}
	return readReply(bufio.NewReader(c))
}

func readReply(br *bufio.Reader) (any, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, errors.New("redis: empty reply")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, errors.New("redis: " + line[1:])
	case ':':
		return strconv.ParseInt(line[1:], 10, 64)
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		return buf[:n], nil
	case '*':
		n, _ := strconv.Atoi(line[1:])
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := readReply(br)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, fmt.Errorf("redis: unknown reply %q", line)
}

func (r *Redis) cmd(ctx context.Context, args ...string) (any, error) {
	c, err := r.conn(ctx)
	if err != nil {
		return nil, err
	}
	v, err := r.do(ctx, c, args...)
	r.release(c, err != nil)
	return v, err
}

func (r *Redis) Get(ctx context.Context, key string) ([]byte, error) {
	v, err := r.cmd(ctx, "GET", r.Prefix+key)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, ErrNotFound
	}
	return v.([]byte), nil
}

func (r *Redis) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	v, err := r.cmd(ctx, "SET", r.Prefix+key, string(value), "NX", "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	if err != nil {
		return false, err
	}
	return v != nil, nil
}

func (r *Redis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	_, err := r.cmd(ctx, "SET", r.Prefix+key, string(value), "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	return err
}

func (r *Redis) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	v, err := r.cmd(ctx, "INCR", r.Prefix+key)
	if err != nil {
		return 0, err
	}
	n := v.(int64)
	if n == 1 {
		_, _ = r.cmd(ctx, "PEXPIRE", r.Prefix+key, strconv.FormatInt(ttl.Milliseconds(), 10))
	}
	return n, nil
}

func (r *Redis) Ping(ctx context.Context) error {
	v, err := r.cmd(ctx, "PING")
	if err != nil {
		return err
	}
	if s, _ := v.(string); s != "PONG" {
		return fmt.Errorf("redis: unexpected ping reply %v", v)
	}
	return nil
}
