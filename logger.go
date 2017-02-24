package freki

import (
	"fmt"
	stdlog "log"
	"os"
)

var logger Logger

func init() {
	logger = NewStandardLogger(stdlog.New(os.Stderr, "", stdlog.LstdFlags))
}

func GetDefaultLogger() Logger {
	return logger
}

func SetDefaultLogger(log Logger) {
	logger = log
}

type Logger interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Panic(args ...interface{})
	Panicf(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
}

type StandardLogger struct {
	slog *stdlog.Logger
}

func NewStandardLogger(slog *stdlog.Logger) *StandardLogger {
	return &StandardLogger{
		slog: slog,
	}
}

func (s *StandardLogger) Debug(args ...interface{}) {
	s.slog.Printf("DEBUG %s", fmt.Sprint(args...))
}

func (s *StandardLogger) Debugf(format string, args ...interface{}) {
	s.Debug(fmt.Sprintf(format, args...))
}

func (s *StandardLogger) Error(args ...interface{}) {
	s.slog.Printf("ERROR %s", fmt.Sprint(args...))
}

func (s *StandardLogger) Errorf(format string, args ...interface{}) {
	s.Error(fmt.Sprintf(format, args...))
}

func (s *StandardLogger) Fatal(args ...interface{}) {
	s.slog.Fatalf("FATAL %s", fmt.Sprint(args...))
}

func (s *StandardLogger) Fatalf(format string, args ...interface{}) {
	s.Fatal(fmt.Sprintf(format, args...))
}

func (s *StandardLogger) Info(args ...interface{}) {
	s.slog.Printf("INFO %s", fmt.Sprint(args...))
}

func (s *StandardLogger) Infof(format string, args ...interface{}) {
	s.Info(fmt.Sprintf(format, args...))
}

func (s *StandardLogger) Panic(args ...interface{}) {
	s.slog.Panicf("PANIC %s", fmt.Sprint(args...))
}

func (s *StandardLogger) Panicf(format string, args ...interface{}) {
	s.Panic(fmt.Sprintf(format, args...))
}

func (s *StandardLogger) Warn(args ...interface{}) {
	s.slog.Printf("WARN %s", fmt.Sprint(args...))
}

func (s *StandardLogger) Warnf(format string, args ...interface{}) {
	s.Warn(fmt.Sprintf(format, args...))
}
