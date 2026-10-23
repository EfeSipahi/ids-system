// Command ids-dashboard shows the records of the IDS in a browser, behind
// a login and over HTTPS (V1–V7, main plan section 11.22).
//
//	ids-dashboard -add-user admin        # prints the new password once
//	ids-dashboard                        # serves https://127.0.0.1:8443
//
// The dashboard only reads the record files that ids-offline (and later
// the ids service) writes; it changes nothing (V2). Users are kept in the
// state directory as salted PBKDF2 hashes. -add-user and -reset-password
// make a random password and print it once; -remove-user removes a user.
// A running dashboard notices these changes without a restart.
//
// Without tls_cert and tls_key in the configuration the dashboard makes
// its own certificate and prints its SHA-256 fingerprint, to compare with
// what the browser shows before accepting it. There is no plain HTTP.
//
// Exit status: 0 on success, 2 when the configuration, the users or the
// certificate cannot be loaded, or the address cannot be used.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/EfeSipahi/ids-system/internal/dashboard"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ids-dashboard", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "configs/dashboard.json", "dashboard configuration `file`")
	addUser := flags.String("add-user", "", "add a user `name` with a new random password, print the password, and exit")
	resetPassword := flags.String("reset-password", "", "give the user `name` a new random password, print it, and exit")
	removeUser := flags.String("remove-user", "", "remove the user `name` and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "ids-dashboard: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	commands := 0
	for _, v := range []string{*addUser, *resetPassword, *removeUser} {
		if v != "" {
			commands++
		}
	}
	if commands > 1 {
		fmt.Fprintln(stderr, "ids-dashboard: use only one of -add-user, -reset-password and -remove-user")
		return 2
	}

	cfg, err := dashboard.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "ids-dashboard: %v\n", err)
		return 2
	}

	switch {
	case *addUser != "":
		password, err := dashboard.AddUser(cfg.StateDir, *addUser)
		if err != nil {
			fmt.Fprintf(stderr, "ids-dashboard: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "Added user %s. Password (shown only now): %s\n", *addUser, password)
		return 0
	case *resetPassword != "":
		password, err := dashboard.ResetPassword(cfg.StateDir, *resetPassword)
		if err != nil {
			fmt.Fprintf(stderr, "ids-dashboard: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "New password for %s (shown only now): %s\n", *resetPassword, password)
		return 0
	case *removeUser != "":
		if err := dashboard.RemoveUser(cfg.StateDir, *removeUser); err != nil {
			fmt.Fprintf(stderr, "ids-dashboard: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "Removed user %s.\n", *removeUser)
		return 0
	}

	srv, err := dashboard.New(cfg, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "ids-dashboard: %v\n", err)
		return 2
	}
	cert, made, err := srv.Certificate()
	if err != nil {
		fmt.Fprintf(stderr, "ids-dashboard: certificate: %v\n", err)
		return 2
	}
	ln, err := net.Listen("tcp", srv.Addr())
	if err != nil {
		fmt.Fprintf(stderr, "ids-dashboard: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "Dashboard: %s\n", srv.URL())
	switch {
	case cfg.TLSCert != "":
		fmt.Fprintf(stdout, "Certificate: %s\n", cfg.TLSCert)
	case made:
		fmt.Fprintln(stdout, "Made a new certificate for this dashboard.")
	}
	fmt.Fprintf(stdout, "Certificate SHA-256 fingerprint: %s\n", dashboard.Fingerprint(cert))
	fmt.Fprintf(stdout, "Reading records from %s\n", cfg.RecordsDir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Serve(ctx, ln, cert); err != nil {
		fmt.Fprintf(stderr, "ids-dashboard: %v\n", err)
		return 2
	}
	return 0
}
