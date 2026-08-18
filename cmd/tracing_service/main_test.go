package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestNewLoggerWritesJsonWithTheDataset(t *testing.T) {
	t.Parallel()

	var builder strings.Builder

	logger := newLogger(&builder)
	logger.Info("test message")

	line := builder.String()
	for _, expected := range []string{`"message":"test message"`, `"dataset":"tracing"`} {
		if !strings.Contains(line, expected) {
			t.Errorf("expected the log line to contain %s, got:\n%s", expected, line)
		}
	}
}

func TestNewEventHandlerCarriesNoDatasetOfItsOwn(t *testing.T) {
	t.Parallel()

	var builder strings.Builder

	handler := newEventHandler(&builder)

	record := slog.NewRecord(time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC), slog.LevelInfo, "an event", 0)
	record.AddAttrs(slog.String("action", "tcp_connect"))

	if err := handler.Handle(context.Background(), record); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	line := builder.String()
	if !strings.Contains(line, `"message":"an event"`) {
		t.Errorf("expected the event message, got:\n%s", line)
	}

	if !strings.Contains(line, `"action":"tcp_connect"`) {
		t.Errorf("expected the event attributes, got:\n%s", line)
	}

	// The tracers each name their own dataset, so the shared handler must not
	// stamp one on every event.
	if strings.Contains(line, `"dataset"`) {
		t.Errorf("expected no dataset from the event handler, got:\n%s", line)
	}
}
