package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/log"
	"github.com/satyrius/gonx"
)

var (
	Version    = "0.0.0.dev"
	addr       = flag.String("web.listen-address", ":9117", "The address to listen on for HTTP requests.")
	pattern    = flag.String("file.pattern", "/var/log/nginx/*.log", "The log pattern")
	sleep      = 10 * time.Second
	combined   = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
	isJson     = flag.Bool("file.json", false, "Logformat JSON")
	parser     *gonx.Parser
	timeFormat = "02/Jan/2006:15:04:05 -0700"
)

func init() {
	lvlStr := os.Getenv("LOGLEVEL")
	if lvlStr != "" {
		lvl, err := logrus.ParseLevel(strings.ToLower(lvlStr))
		if err == nil {
			logrus.SetLevel(lvl)
		}
	}
	parser = gonx.NewParser(combined)
}

type logfields struct {
	RemoteAddr    string `json:"remote_addr"`
	RemoteUser    string `json:"remote_user"`
	BodyBytesSent string `json:"body_bytes_sent"`
	RequestTime   string `json:"request_time"`
	Code          string `json:"status"`
	Request       string `json:"request"`
	Method        string `json:"request_method"`
	Referer       string `json:"http_referer"`
	UserAgent     string `json:"http_user_agent"`
}

type logline struct {
	Timestamp time.Time `json:"@timestamp"`
	Fields    logfields `json:"@fields"`
}

type nginxCollector struct {
	pattern string
	reqs    *prometheus.CounterVec
	t0      time.Time
	cont    uint32
}

func New(p string) *nginxCollector {
	cv := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests made.",
		ConstLabels: prometheus.Labels{
			"handler": "nginx-log-exporter",
		},
	}, []string{"method", "code", "file"})
	reqCv := prometheus.MustRegisterOrGet(cv).(*prometheus.CounterVec)
	return &nginxCollector{
		pattern: p,
		reqs:    reqCv,
		t0:      time.Now().UTC(),
	}
}

func (n *nginxCollector) start() {
	atomic.StoreUint32(&n.cont, 1)
}

func (n *nginxCollector) stop() {
	atomic.StoreUint32(&n.cont, 0)
}

func (n *nginxCollector) running() bool {
	v := atomic.LoadUint32(&n.cont)
	if v > 0 {
		return true
	}
	return false
}

func (n *nginxCollector) Run() {
	logrus.Debugf("Watching pattern %s ...", n.pattern)
	for {
		n.t0 = time.Now().UTC()
		n.start()
		for _, fn := range globFiles(n.pattern) {
			go n.watchFilename(fn)
		}
		time.Sleep(sleep * 6 * 10)
		logrus.Infof("Re-scanning pattern %s ...", n.pattern)
		n.stop()
		time.Sleep(sleep * 2)
	}
}

func (n *nginxCollector) watchFilename(fn string) {
	logrus.Infof("Watching file %s ...", fn)
	for {
		if err := n.watchFile(fn); err != nil {
			logrus.Warnf("Error watching file %s: %s", fn, err)
		}
		time.Sleep(sleep)
	}
}

func (n *nginxCollector) watchFile(fn string) error {
	dev0, ino0, err := filestate(fn)
	if err != nil {
		return fmt.Errorf("failed to get file state %s: %s", fn, err)
	}
	var offset int64
	for {
		devN, inoN, err := filestate(fn)
		if err != nil {
			return fmt.Errorf("failed to get file state %s: %s", fn, err)
		}
		if inoN != ino0 || devN != dev0 {
			// file changed (was rotated, moved, etc.)
			return fmt.Errorf("file changed (inode %d -> %d, dev %d -> %d)", ino0, inoN, dev0, devN)
		}
		fh, err := os.Open(fn)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %s", fn, err)
		}
		_, err = fh.Seek(offset, 0)
		if err != nil {
			fmt.Errorf("failed to seek to position %d: %s", offset, err)
		}
		lines := 0
		reader := bufio.NewReader(fh)
	LINE:
		for {
			line, err := reader.ReadBytes('\n')
			line = bytes.TrimRight(line, "\n\r")
			if len(line) > 0 {
				lines++
				if err := n.parseLine(fn, line); err != nil {
					logrus.Debugf("Failed to parse line %s: %s", string(line), err)
				}
			}
			if err != nil {
				if err != io.EOF {
					return fmt.Errorf("failed to finish reading file %s: %s", fn, err)
				}
				break LINE
			}
		}
		offset, err = fh.Seek(0, os.SEEK_CUR)
		if err != nil {
			return fmt.Errorf("failed to get current position %s: %s", fn, err)
		}
		fh.Close()
		logrus.Debugf("Finished reading %s at %d. Read %d lines. Sleeping ...", fn, offset, lines)
		if !n.running() {
			return nil
		}
		time.Sleep(sleep)
	}
}

func (n *nginxCollector) parseLine(fn string, ln []byte) error {
	var ll logline
	if *isJson {
		err := json.Unmarshal(ln, &ll)
		if err != nil {
			return err
		}
	} else {
		ge, err := parser.ParseString(string(ln))
		if err != nil {
			return err
		}
		tl, _ := ge.Field("time_local")
		ts, err := time.Parse(timeFormat, tl)
		if err != nil {
			return err
		}
		ll = logline{
			Timestamp: ts,
			Fields:    logfields{},
		}
		ll.Fields.RemoteAddr, _ = ge.Field("remote_addr")
		ll.Fields.RemoteUser, _ = ge.Field("remote_user")
		ll.Fields.BodyBytesSent, _ = ge.Field("body_bytes_sent")
		ll.Fields.Code, _ = ge.Field("status")
		req, _ := ge.Field("request")
		p := strings.Split(req, " ")
		if len(p) > 1 {
			ll.Fields.Method = p[0]
			ll.Fields.Request = p[1]
		}
		ll.Fields.Referer, _ = ge.Field("http_referer")
		ll.Fields.UserAgent, _ = ge.Field("http_user_agent")
	}
	if ll.Timestamp.UTC().Before(n.t0) {
		return fmt.Errorf("Ignoring old request: %s < %s", ll.Timestamp.UTC().Format(time.RFC3339), n.t0.Format(time.RFC3339))
	}
	n.reqs.WithLabelValues(strings.ToLower(ll.Fields.Method), ll.Fields.Code, fn).Inc()
	return nil
}

func filestate(fn string) (uint64, uint64, error) {
	info, err := os.Stat(fn)
	if err != nil {
		return 0, 0, err
	}
	fstat := info.Sys().(*syscall.Stat_t)
	return fstat.Dev, fstat.Ino, nil
}

func main() {
	flag.Parse()

	nc := New(*pattern)
	go nc.Run()

	http.Handle("/metrics", prometheus.UninstrumentedHandler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
		<head><title>nginx Log Exporter</title></head>
		<body>
		<h1>nginx Log Exporter</h1>
		<p><a href="/metrics">Metrics</a></p>
		</body>
		</html>`))
	})

	log.Infof("Starting nginxlog_exporter v%s at %s", Version, *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatalf("Error starting HTTP server: %s", err)
	}
}

// globFiles will try to expand the logfile pattern
func globFiles(logfile string) []string {
	logfiles := make([]string, 0)
	matches, err := filepath.Glob(logfile)
	if err != nil {
		logfiles = append(logfiles, logfile)
	} else {
		logfiles = append(logfiles, matches...)
	}
	return logfiles
}
