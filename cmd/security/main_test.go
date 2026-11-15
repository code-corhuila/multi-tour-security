package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/verification"
)

func TestC_ServerAnswersAndStopsWhenAsked(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}), slog.New(slog.NewJSONHandler(io.Discard, nil)), func(context.Context) error { return nil })
	}()

	resp, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("an orderly shutdown must return nil, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not stop after the context ended")
	}
}

func TestC_TheSendOfTheFirstLinkEndsWellBeforeTheServerCutsTheConnection(t *testing.T) {
	if verification.SendTimeout+3*time.Second > writeTimeout {
		t.Fatalf("a send of up to %s inside a request that the server cuts after %s leaves the person with a reset instead of the answer", verification.SendTimeout, writeTimeout)
	}
}

func TestC_TheShutdownWaitsForTheWorkThatIsStillRunning(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	var finished atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, listener, http.NotFoundHandler(), slog.New(slog.NewJSONHandler(io.Discard, nil)), func(wait context.Context) error {
			select {
			case <-time.After(400 * time.Millisecond):
				finished.Store(true)
				return nil
			case <-wait.Done():
				return wait.Err()
			}
		})
	}()
	time.Sleep(100 * time.Millisecond)
	stop()
	select {
	case err := <-done:
		if err != nil || !finished.Load() {
			t.Fatalf("serve returned (%v) before the work in flight ended (finished=%v)", err, finished.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not stop")
	}
}

func TestC_AWorkThatOverrunsTheShutdownIsLoggedAndTheServerStillStops(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	var logs bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, listener, http.NotFoundHandler(), slog.New(slog.NewJSONHandler(&logs, nil)), func(context.Context) error {
			return context.DeadlineExceeded // the work did not end within the budget
		})
	}()
	time.Sleep(100 * time.Millisecond)
	stop()
	select {
	case err := <-done:
		if err != nil || !strings.Contains(logs.String(), "did not end in time") {
			t.Fatalf("err = %v, log = %s: an overrun must be logged and must not be an error of the shutdown", err, logs.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not stop")
	}
}
