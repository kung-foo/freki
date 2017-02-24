package freki

import (
	"bytes"
	"log"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestLogger(t *testing.T) {
	Convey("The wrapped logger should", t, func() {
		buff := new(bytes.Buffer)
		testLogger := NewStandardLogger(log.New(buff, "", log.LstdFlags))

		testLogger.Debug("hello")
		So(buff.String(), ShouldEndWith, "DEBUG hello\n")
		buff.Reset()

		testLogger.Debug("hello", "world")
		So(buff.String(), ShouldEndWith, "DEBUG helloworld\n")
		buff.Reset()

		testLogger.Debugf("hello %s", "world")
		So(buff.String(), ShouldEndWith, "DEBUG hello world\n")
		buff.Reset()

		testLogger.Error("hello")
		So(buff.String(), ShouldEndWith, "ERROR hello\n")
		buff.Reset()

		testLogger.Error("hello", "world")
		So(buff.String(), ShouldEndWith, "ERROR helloworld\n")
		buff.Reset()

		testLogger.Errorf("hello %s", "world")
		So(buff.String(), ShouldEndWith, "ERROR hello world\n")
		buff.Reset()

		testLogger.Info("hello")
		So(buff.String(), ShouldEndWith, "INFO hello\n")
		buff.Reset()

		testLogger.Info("hello", "world")
		So(buff.String(), ShouldEndWith, "INFO helloworld\n")
		buff.Reset()

		testLogger.Infof("hello %s", "world")
		So(buff.String(), ShouldEndWith, "INFO hello world\n")
		buff.Reset()

		testLogger.Warn("hello")
		So(buff.String(), ShouldEndWith, "WARN hello\n")
		buff.Reset()

		testLogger.Warn("hello", "world")
		So(buff.String(), ShouldEndWith, "WARN helloworld\n")
		buff.Reset()

		testLogger.Warnf("hello %s", "world")
		So(buff.String(), ShouldEndWith, "WARN hello world\n")
		buff.Reset()
	})
}
