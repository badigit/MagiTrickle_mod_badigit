//go:build linux || darwin

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestConsoleLogStreams(t *testing.T) {
	for _, tc := range []struct {
		level  zerolog.Level
		prefix string
		stderr bool
	}{
		{zerolog.TraceLevel, "TRC", false},
		{zerolog.DebugLevel, "DBG", false},
		{zerolog.InfoLevel, "INF", false},
		{zerolog.WarnLevel, "WRN", false},
		{zerolog.ErrorLevel, "ERR", true},
		{zerolog.FatalLevel, "FTL", true},
		{zerolog.PanicLevel, "PNC", true},
		{zerolog.NoLevel, "???", false},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			writer := newConsoleLogWriter(&stdout, &stderr)
			writer.stdout.NoColor = true
			writer.stderr.NoColor = true
			logger := zerolog.New(writer)
			logger.WithLevel(tc.level).Msg("test message")

			want, other := &stdout, &stderr
			if tc.stderr {
				want, other = &stderr, &stdout
			}
			if !strings.Contains(want.String(), tc.prefix+" test message") || other.Len() != 0 {
				t.Fatalf("unexpected log streams: stdout=%q stderr=%q", &stdout, &stderr)
			}
		})
	}
}
