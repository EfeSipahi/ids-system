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
	exit := 0
	select {
	case sig := <-signals:
		fmt.Fprintf(stdout, "Stopping (%v)\n", sig)
	case err := <-served:
		logger.Printf("stopping: %v", err)
		exit = 1
	}
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
