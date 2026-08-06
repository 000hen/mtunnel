package nat

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/pion/logging"
)

// logFactory adapts pion's LeveledLogger contract onto log/slog, so an ICE failure
// is diagnosable instead of opaque. pion's own DefaultLoggerFactory writes plain
// text to stderr, which is where this binary emits JSON diagnostic records - mixing
// the two would corrupt a log stream a supervisor is parsing.
//
// When diagnostics are off every level is dropped: the punch only ever runs to
// produce those records, so there is nothing to say when nobody is listening.
type logFactory struct {
	diagnostic bool
}

func (f logFactory) NewLogger(scope string) logging.LeveledLogger {
	return iceLogger{scope: scope, enabled: f.diagnostic}
}

// iceLogger maps pion's five levels onto three slog levels. pion logs
// per-candidate and per-binding-request detail at info, which is far too chatty for
// slog's info level, so info is demoted to debug and trace/debug are dropped
// outright rather than merely demoted.
type iceLogger struct {
	scope   string
	enabled bool
}

func (l iceLogger) Trace(string)              {}
func (l iceLogger) Tracef(string, ...any)     {}
func (l iceLogger) Debug(string)              {}
func (l iceLogger) Debugf(string, ...any)     {}
func (l iceLogger) Info(msg string)           { l.emit(slog.LevelDebug, msg) }
func (l iceLogger) Warn(msg string)           { l.emit(slog.LevelWarn, msg) }
func (l iceLogger) Error(msg string)          { l.emit(slog.LevelError, msg) }
func (l iceLogger) Infof(f string, a ...any)  { l.emitf(slog.LevelDebug, f, a...) }
func (l iceLogger) Warnf(f string, a ...any)  { l.emitf(slog.LevelWarn, f, a...) }
func (l iceLogger) Errorf(f string, a ...any) { l.emitf(slog.LevelError, f, a...) }

func (l iceLogger) emit(level slog.Level, msg string) {
	if !l.enabled {
		return
	}
	slog.Log(context.Background(), level, "tunnel_nat_ice", "scope", l.scope, "message", msg)
}

// emitf formats only once it knows the record will be emitted, so a disabled logger
// costs nothing beyond the call itself - pion calls these on hot paths.
func (l iceLogger) emitf(level slog.Level, format string, args ...any) {
	if !l.enabled {
		return
	}
	l.emit(level, fmt.Sprintf(format, args...))
}
