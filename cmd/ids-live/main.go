// Command ids-live analyses copies of live traffic (A01). A proxy's copier,
// such as the Caddy module ids_copy, sends a copy of each request and its
// response over a Unix socket; ids-live runs the same rules and profiles on
// it as ids-offline, and writes the records the dashboard reads.
//
//	ids-live -config configs/site.json
//
// The configuration needs a "live" section, or -socket, and a "records"
// section, or -records. The site never waits for ids-live (M09): copies
// wait in a queue with a size limit, and the ones that do not fit are
// dropped and counted in gap records (T7, T8).
//
// While it runs it reads its configuration, rule files and profiles again
// every few seconds (-watch). When they changed and load, it takes them
// without stopping: the next copies are analysed with the new rules, and a
// new run starts in the records, whose start record carries the new
// fingerprint (W13 of docs/development-plan-dashboard-control.md). When
// they don't load, it keeps the ones it runs and says why on standard
// error. The records folder and the live section take effect at the next
// start.
//
// SIGTERM or SIGINT stops it. It stops reading, analyses what is queued
// for up to 10 seconds, counts what is left in a gap record, and closes
// the records.
//
// It never prints a value of a request. Connection events and errors go to
// standard error.
//
// Exit status: 0 after a stop, 1 when the socket or the records fail while
// running, 2 when it cannot start.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/live"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
	"github.com/EfeSipahi/ids-system/internal/result"
)

// drainTime is how long a stop waits for the queued copies to be analysed.
const drainTime = 10 * time.Second

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, signals))
}

func run(args []string, stdout, stderr io.Writer, signals <-chan os.Signal) int {
	flags := flag.NewFlagSet("ids-live", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "configs/crs-first-engine.json", "product configuration `file`")
	socket := flags.String("socket", "", "listen on this Unix socket `path`, in place of the one in the configuration")
	recordsDir := flags.String("records", "", "write records to this `directory`, in place of the one in the configuration")
	watchEvery := flags.Duration("watch", 3*time.Second, "read the configuration again this often and take a change without stopping; 0 turns it off")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "ids-live: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "ids-live: "+format+"\n", a...)
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fail("%v", err)
	}
	lc := live.Config{}
	if cfg.Live != nil {
		lc = *cfg.Live
	}
	if *socket != "" {
		lc.Socket = *socket
	}
	if lc.Socket == "" {
		return fail("%s has no \"live\" section with a socket; add one, or give -socket", *configPath)
	}
	lc = lc.WithDefaults()
	if err := lc.Validate(); err != nil {
		return fail("%v", err)
	}
	if cfg.Records == nil && *recordsDir == "" {
		return fail("%s has no \"records\" section; add one, or give -records", *configPath)
	}
	rc := record.Config{}
	if cfg.Records != nil {
		rc = *cfg.Records
	}
	if *recordsDir != "" {
		rc.Dir = *recordsDir
	}

	rules, err := engine.Load(cfg.Config)
	if err != nil {
		return fail("the rules cannot be loaded:\n%v", err)
	}
	apps, err := profile.NewSet(rules, cfg.Applications, cfg.RequireProfile)
	if err != nil {
		return fail("the applications cannot be prepared:\n%v", err)
	}
	startup := result.NewStartup(rules)
	startup.SetApplications(apps)
	result.WriteStartup(stdout, startup, true, "run ids-offline -config "+*configPath)

	fingerprint, err := cfg.Fingerprint(rules.ParanoiaLevel())
	if err != nil {
		return fail("%v", err)
	}
	recorder, err := record.OpenWith(rc, record.NewEngine(rules, fingerprint), rules.Statuses(), apps,
		&record.Input{Kind: record.InputLive, Socket: lc.Socket})
	if err != nil {
		return fail("%v", err)
	}
	logger := log.New(stderr, "ids-live: ", log.LstdFlags)
	analyzer := &live.Analyzer{Rules: rules, Apps: apps, Recorder: recorder, Parsing: cfg.Parsing()}
	srv, err := live.Listen(lc, recorder, analyzer.Analyze, logger)
	if err != nil {
		recorder.Close()
		return fail("%v", err)
	}
	fmt.Fprintf(stdout, "Listening on %s: %d workers, a queue of %d copies or %d MB, frames up to %d MB\n",
		lc.Socket, lc.Workers, lc.QueueCopies, lc.QueueMB, lc.MaxFrameMB)
	fmt.Fprintf(stdout, "Records: %s (run %s)\n", rc.Dir, recorder.Run())

	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	watchCtx, stopWatching := context.WithCancel(context.Background())
	defer stopWatching()
	if *watchEvery > 0 {
		w := &watcher{path: *configPath, current: fingerprint, live: lc, socket: *socket, recordsDir: rc.Dir, recordsFlag: *recordsDir != "",
			analyzer: analyzer, recorder: recorder, log: logger, out: stdout}
		go w.run(watchCtx, *watchEvery)
	}
	exit := 0
	select {
	case sig := <-signals:
		fmt.Fprintf(stdout, "Stopping (%v)\n", sig)
	case err := <-served:
		logger.Printf("stopping: %v", err)
		exit = 1
	}
	stopWatching()
	ctx, cancel := context.WithTimeout(context.Background(), drainTime)
	stats := srv.Shutdown(ctx)
	cancel()
	if err := recorder.Close(); err != nil {
		logger.Printf("%v", err)
		exit = 1
	}
	fmt.Fprintf(stdout, "Stopped: %d copies received, %d analysed, %d not analysed (%d with a full queue, %d at the stop), %d whose record could not be written; copiers reported %d not sent\n",
		stats.Received, stats.Analysed, stats.Dropped+stats.Stopped, stats.Dropped, stats.Stopped, stats.Failed, stats.Missed)
	return exit
}

// watcher takes a changed configuration without stopping (W13).
type watcher struct {
	path    string
	current string // the fingerprint ids-live runs
	live    live.Config
	socket  string // -socket, which wins over the configuration
	// recordsDir is the folder the recorder locked; recordsFlag is true
	// when -records named it.
	recordsDir  string
	recordsFlag bool
	analyzer    *live.Analyzer
	recorder    *record.Recorder
	log         *log.Logger
	out         io.Writer
	// said is the last problem written, so that it is written once.
	said string
}

func (w *watcher) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.check()
		}
	}
}

// problem writes a problem once, until another one or a success.
func (w *watcher) problem(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if msg != w.said {
		w.log.Print(msg)
		w.said = msg
	}
}

// check reads the configuration and takes it when it changed and loads.
func (w *watcher) check() {
	cfg, err := config.Load(w.path)
	if err != nil {
		w.problem("the configuration on disk does not load, so ids-live keeps the one it runs: %v", err)
		return
	}
	fp, err := cfg.Fingerprint(cfg.Level())
	if err != nil {
		w.problem("the configuration on disk can't be read, so ids-live keeps the one it runs: %v", err)
		return
	}
	if fp == w.current {
		w.said = ""
		return
	}
	rules, err := engine.Load(cfg.Config)
	if err != nil {
		w.problem("the rules of the changed configuration do not load, so ids-live keeps the ones it runs:\n%v", err)
		return
	}
	apps, err := profile.NewSet(rules, cfg.Applications, cfg.RequireProfile)
	if err != nil {
		w.problem("the applications of the changed configuration can't be prepared, so ids-live keeps the ones it runs:\n%v", err)
		return
	}
	rc := record.Config{Dir: w.recordsDir}
	if cfg.Records != nil {
		rc = *cfg.Records
		if w.recordsFlag {
			rc.Dir = w.recordsDir
		}
	}
	if filepath.Clean(rc.Dir) != filepath.Clean(w.recordsDir) {
		w.log.Printf("the records folder changed to %s; that takes effect when ids-live starts again, and until then it writes to %s", rc.Dir, w.recordsDir)
		rc.Dir = w.recordsDir
	}
	lc := live.Config{}
	if cfg.Live != nil {
		lc = *cfg.Live
	}
	if w.socket != "" {
		lc.Socket = w.socket
	}
	if lc.WithDefaults() != w.live {
		w.log.Printf("the live section changed; it takes effect when ids-live starts again")
	}
	if err := w.recorder.Restart(rc, record.NewEngine(rules, fp), rules.Statuses(), apps); err != nil {
		w.problem("the changed configuration can't be taken, so ids-live keeps the one it runs: %v", err)
		return
	}
	w.analyzer.Use(rules, apps, cfg.Parsing())
	w.current, w.said = fp, ""
	fmt.Fprintf(w.out, "Took the changed configuration: run %s, fingerprint %s\n", w.recorder.Run(), fp)
}
