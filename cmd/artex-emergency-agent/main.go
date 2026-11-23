// artex-emergency-agent is a minimal, privileged, Unix-socket-only gateway.
// It should run on the actual nftables host/network namespace, with only the
// kernel capabilities needed to update a preprovisioned exclusive timeout set.
// DO NOT bind it to TCP, expose it through a reverse proxy or add an AI agent.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/containment"
	"github.com/Autumn-27/artex/defense"
)

func run() error {
	if runtime.GOOS != "linux" {
		return errors.New("the emergency gateway requires Linux")
	}
	cfg, err := defense.LoadEmergencyConfig()
	if err != nil {
		return err
	}
	if cfg.Mode != defense.EmergencyNFT {
		return errors.New("ARTEX_AUTO_CONTAIN_MODE must be nftables for the host helper")
	}
	path := os.Getenv("ARTEX_AUTO_CONTAIN_SOCKET")
	if path == "" {
		path = "/run/artex/emergency.sock"
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("containment socket path must be absolute and normalized")
	}
	dir := filepath.Dir(path)
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return errors.New("socket parent must be a directory without group/world write access")
	}
	// Never unlink a pre-existing socket or symlink. Require the operator to
	// stop the prior helper and clean up its socket deliberately.
	if _, err := os.Lstat(path); err == nil {
		return errors.New("emergency socket already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := (containment.NFTRunner{}).Check(ctx); err != nil {
		cancel()
		return err
	}
	cancel()
	lis, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer lis.Close()
	defer os.Remove(path)
	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	server := &http.Server{
		Handler:           containment.Handler(cfg, containment.NFTRunner{}),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
	}
	go func() {
		<-ctx.Done()
		drain, release := context.WithTimeout(context.Background(), 3*time.Second)
		defer release()
		_ = server.Shutdown(drain)
	}()
	log.Printf("ARTEX emergency helper ready on a Unix socket; no TCP listener")
	if err := server.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Printf("emergency helper refused startup: %v", err)
		os.Exit(1)
	}
}
