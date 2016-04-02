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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/log"
)

var Version = "0.0.0.dev"
var addr = flag.String("web.listen-address", ":9117", "The address to listen on for HTTP requests.")
var pattern = flag.String("file.pattern", "/var/log/nginx/*.log", "The log pattern")
var rescan = flag.String("file.rescan", "10", "Rescan interval in minutes")
var sleep = 10 * time.Second

func init() {
	lvlStr := os.Getenv("LOGLEVEL")
	if lvlStr != "" {
		lvl, err := logrus.ParseLevel(strings.ToLower(lvlStr))
		if err == nil {
			logrus.SetLevel(lvl)
		}
	}
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
	errs    *prometheus.CounterVec
	t0      time.Time
	cont    uint32
	wg      sync.WaitGroup
	rescan  time.Duration
}

func New(p string, rs string) *nginxCollector {
	cv := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests made.",
		ConstLabels: prometheus.Labels{
			"handler": "nginx-log-exporter",
		},
	}, []string{"method", "code", "file"})
	regCv := prometheus.MustRegisterOrGet(cv).(*prometheus.CounterVec)
	errs := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nginxlog_exporter_errors_total",
		Help: "Total number of nginxlog exporter errors.",
		ConstLabels: prometheus.Labels{
			"handler": "nginx-log-exporter",
		},
	}, []string{"type"})
	regErrs := prometheus.MustRegisterOrGet(errs).(*prometheus.CounterVec)
	n := &nginxCollector{
		pattern: p,
		reqs:    regCv,
		errs:    regErrs,
		t0:      time.Now().UTC(),
		rescan:  sleep * 6 * 10,
	}
	if rescan, err := strconv.Atoi(rs); err == nil {
		n.rescan = sleep * time.Duration(rescan) * 6
	}
	return n
}

func (n *nginxCollector) Run() {
	logrus.Debugf("Watching pattern %s. Rescan every %s", n.pattern, n.rescan)
	for {
		n.t0 = time.Now().UTC()
		n.start()
		for _, fn := range globFiles(n.pattern) {
			go n.watchFilename(fn)
		}
		time.Sleep(n.rescan)
		logrus.Infof("Re-scanning pattern %s ...", n.pattern)
		n.stop()
		n.wg.Wait()
	}
}

func (n *nginxCollector) watchFilename(fn string) {
	n.wg.Add(1)
	defer n.wg.Done()
	logrus.Infof("Watching file %s ...", fn)
	for {
		err := n.watchFile(fn)
		if err == nil {
			logrus.Debugf("Stopping to watch file %s", fn)
			return
		}
		n.errs.WithLabelValues("file").Inc()
		logrus.Warnf("Error watching file %s: %s. Will retry after %s", fn, err, sleep)
		time.Sleep(sleep)
	}
}

func (n *nginxCollector) watchFile(fn string) error {
	dev0, ino0, err := filestate(fn)
	if err != nil {
		return fmt.Errorf("failed to get file state %s: %s", fn, err)
	}
	var offset int64
	var lines int
	for {
		devN, inoN, err := filestate(fn)
		if err != nil {
			return fmt.Errorf("failed to get file state %s: %s", fn, err)
		}
		if inoN != ino0 || devN != dev0 {
			// file changed (was rotated, moved, etc.)
			return fmt.Errorf("file changed (inode %d -> %d, dev %d -> %d)", ino0, inoN, dev0, devN)
		}
		offset, lines, err = n.readLines(fn, offset)
		if err != nil {
			return err
		}
		if lines > 0 {
			logrus.Debugf("Finished reading %s at %d. Read %d lines. Sleeping ...", fn, offset, lines)
		}
		if !n.running() {
			return nil
		}
		time.Sleep(sleep)
	}
}

func (n *nginxCollector) readLines(fn string, offset int64) (int64, int, error) {
	var lines int
	fh, err := os.Open(fn)
	if err != nil {
		return offset, lines, fmt.Errorf("failed to open file %s: %s", fn, err)
	}
	defer fh.Close()
	_, err = fh.Seek(offset, 0)
	if err != nil {
		return offset, lines, fmt.Errorf("failed to seek to position %d: %s", offset, err)
	}
	reader := bufio.NewReader(fh)
LINE:
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				return offset, lines, fmt.Errorf("failed to finish reading file %s: %s", fn, err)
			}
			break LINE
		}
		line = bytes.TrimRight(line, "\n\r")
		if len(line) > 0 {
			err := n.parseLine(fn, line)
			if err != nil {
				n.errs.WithLabelValues("parse").Inc()
				//logrus.Debugf("Failed to parse line %s: %s", string(line), err)
				continue
			}
			lines++
		}
	}
	offset, err = fh.Seek(0, os.SEEK_CUR)
	if err != nil {
		return offset, lines, fmt.Errorf("failed to get current position %s: %s", fn, err)
	}
	return offset, lines, nil
}

func (n *nginxCollector) parseLine(fn string, ln []byte) error {
	// TODO(dschulz) support plain format
	var ll logline
	err := json.Unmarshal(ln, &ll)
	if err != nil {
		return err
	}
	if ll.Timestamp.UTC().Before(n.t0) {
		return fmt.Errorf("Ignoring old request: %s < %s", ll.Timestamp.UTC().Format(time.RFC3339), n.t0.Format(time.RFC3339))
	}
	n.reqs.WithLabelValues(strings.ToLower(ll.Fields.Method), ll.Fields.Code, fn).Inc()
	return nil
}

func filestate(fn string) (uint64, uint64, error) {
	// TODO(dschulz) support win and bsd, too
	info, err := os.Stat(fn)
	if err != nil {
		return 0, 0, err
	}
	fstat := info.Sys().(*syscall.Stat_t)
	return fstat.Dev, fstat.Ino, nil
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

func main() {
	flag.Parse()

	nc := New(*pattern, *rescan)
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
