package ftpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
)

type Config struct {
	Host        string
	Port        int
	User        string
	Password    string
	TLS         bool
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

type Client struct {
	cfg Config
}

func New(cfg Config) *Client {
	if cfg.Port <= 0 {
		cfg.Port = 21
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	if cfg.IOTimeout <= 0 {
		cfg.IOTimeout = 60 * time.Second
	}
	return &Client{cfg: cfg}
}

func (c *Client) Configured() bool {
	return strings.TrimSpace(c.cfg.Host) != "" && strings.TrimSpace(c.cfg.User) != ""
}

// UploadAtomic stores reader to remoteDir/name via .part then rename.
// Verifies SIZE after STOR and after rename.
func (c *Client) UploadAtomic(
	ctx context.Context, remoteDir, name string, r io.Reader, wantBytes int64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !c.Configured() {
		return errors.New("ftp not configured")
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Quit() }()

	dir := NormalizeRemoteDir(remoteDir)
	if err := ensureDirs(conn, dir); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := conn.ChangeDir(dir); err != nil {
		return fmt.Errorf("cwd %s: %w", dir, err)
	}

	finalName := path.Base(name)
	partName := finalName + ".part"
	_ = conn.Delete(partName)

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := conn.Stor(partName, r); err != nil {
		_ = conn.Delete(partName)
		return fmt.Errorf("stor: %w", err)
	}
	if err := verifySize(conn, partName, wantBytes); err != nil {
		_ = conn.Delete(partName)
		return err
	}
	_ = conn.Delete(finalName)
	if err := conn.Rename(partName, finalName); err != nil {
		_ = conn.Delete(partName)
		return fmt.Errorf("rename: %w", err)
	}
	if err := verifySize(conn, finalName, wantBytes); err != nil {
		return err
	}
	return nil
}

// RemoteMatches reports whether remoteDir/name exists with the given size.
func (c *Client) RemoteMatches(ctx context.Context, remoteDir, name string, wantBytes int64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !c.Configured() {
		return false, errors.New("ftp not configured")
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Quit() }()
	dir := NormalizeRemoteDir(remoteDir)
	if err := conn.ChangeDir(dir); err != nil {
		return false, nil
	}
	if err := verifySize(conn, path.Base(name), wantBytes); err != nil {
		return false, nil
	}
	return true, nil
}

func (c *Client) dial(ctx context.Context) (*ftp.ServerConn, error) {
	addr := net.JoinHostPort(c.cfg.Host, fmt.Sprintf("%d", c.cfg.Port))
	opts := []ftp.DialOption{
		ftp.DialWithTimeout(c.cfg.DialTimeout),
	}
	if c.cfg.TLS {
		opts = append(opts, ftp.DialWithExplicitTLS(&tls.Config{
			ServerName: c.cfg.Host,
			MinVersion: tls.VersionTLS12,
		}))
	}
	type result struct {
		conn *ftp.ServerConn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ftp.Dial(addr, opts...)
		if err != nil {
			ch <- result{err: err}
			return
		}
		if err := conn.Login(c.cfg.User, c.cfg.Password); err != nil {
			_ = conn.Quit()
			ch <- result{err: err}
			return
		}
		ch <- result{conn: conn}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.conn, res.err
	}
}

func verifySize(conn *ftp.ServerConn, name string, want int64) error {
	size, err := conn.FileSize(name)
	if err != nil {
		return fmt.Errorf("size %s: %w", name, err)
	}
	if size != want {
		return fmt.Errorf("size mismatch for %s: remote=%d local=%d", name, size, want)
	}
	return nil
}

func NormalizeRemoteDir(dir string) string {
	dir = strings.TrimSpace(dir)
	dir = strings.ReplaceAll(dir, "\\", "/")
	if dir == "" {
		return "/"
	}
	if !strings.HasPrefix(dir, "/") {
		dir = "/" + dir
	}
	return path.Clean(dir)
}

func ensureDirs(conn *ftp.ServerConn, dir string) error {
	if dir == "/" || dir == "" {
		return nil
	}
	parts := strings.Split(strings.Trim(dir, "/"), "/")
	cur := ""
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			continue
		}
		cur += "/" + part
		_ = conn.MakeDir(cur)
	}
	return nil
}

func ValidateRemoteDir(dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return errors.New("remote directory is required")
	}
	if strings.Contains(dir, "..") || strings.ContainsRune(dir, 0) {
		return errors.New("remote directory contains invalid characters")
	}
	return nil
}
