package main

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

func init() {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006/01/02 15:04:05",
		ForceColors:     true,
	})
}

func setupLogging(debug bool) {
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debug("Debug 模式已启用")
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
}

func logRequest(method, url string) {
	logrus.WithFields(logrus.Fields{
		"method": method,
		"url":    url,
	}).Info("HTTP请求")
}

func logResponse(method, url string, statusCode int, statusText string, err error) {
	fields := logrus.Fields{
		"method": method,
		"url":    url,
	}

	if err != nil {
		fields["status"] = "ERROR"
		fields["error"] = err.Error()
	} else {
		if statusText != "" {
			fields["status"] = fmt.Sprintf("%d %s", statusCode, statusText)
		} else {
			fields["status"] = statusCode
		}
	}

	logrus.WithFields(fields).Info("HTTP响应")
}

func logDebug(format string, v ...interface{}) {
	logrus.WithFields(logrus.Fields{
		"type": "debug",
	}).Debugf(format, v...)
}

func logError(format string, v ...interface{}) {
	logrus.WithFields(logrus.Fields{
		"type": "error",
	}).Errorf(format, v...)
}

func logProtocol(format string, v ...interface{}) {
	logrus.WithFields(logrus.Fields{
		"category": "protocol",
	}).Debugf(format, v...)
}

func logTunnel(format string, v ...interface{}) {
	logrus.WithFields(logrus.Fields{
		"category": "tunnel",
	}).Debugf(format, v...)
}

func logTLS(format string, v ...interface{}) {
	logrus.WithFields(logrus.Fields{
		"category": "tls",
	}).Debugf(format, v...)
}

func logHTTP1(format string, v ...interface{}) {
	logrus.WithFields(logrus.Fields{
		"category": "http1",
		"protocol": "http/1.1",
	}).Debugf(format, v...)
}

func logHTTP2(format string, v ...interface{}) {
	logrus.WithFields(logrus.Fields{
		"category": "http2",
		"protocol": "h2",
	}).Debugf(format, v...)
}
