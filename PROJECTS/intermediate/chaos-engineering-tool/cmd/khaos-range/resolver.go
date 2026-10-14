// ©AngelaMos | 2026
// resolver.go

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
)

const (
	flagControl = "control"
	flagZone    = "zone"

	usageControl = "the zone name no fault ever touches"
	usageZone    = "a name this resolver answers authoritatively, as name=address; repeatable"

	errZoneEntry = "%w: %q (expected name=address)"
	errNoZone    = "%w: pass --zone name=address at least once"
)

var errZoneFormat = errors.New("a --zone entry must be name=address")

var errZoneMissing = errors.New(
	"a chaos resolver needs at least one zone entry",
)

// serveResolver runs the same internal/dnsrv package khaos runs outside the
// range, behind a different entry point. It skips roleHandler because it is the
// one role that is not an HTTP service.
func serveResolver(args []string) error {
	flags := flag.NewFlagSet(roleResolver, flag.ContinueOnError)

	control := flags.String(flagControl, "", usageControl)

	var entries zoneEntries
	flags.Var(&entries, flagZone, usageZone)

	if err := flags.Parse(args); err != nil {
		return err
	}

	zone, err := entries.parse()
	if err != nil {
		return err
	}

	// Never from the command line, which is world-readable in the process table.
	resolver, err := dnsrv.New(dnsrv.Config{
		Nonce:   os.Getenv(dockerx.EnvResolverNonce),
		Control: *control,
		Zone:    zone,
	})
	if err != nil {
		return err
	}

	if err := resolver.Serve(); err != nil {
		return err
	}

	if err := resolver.ServeControl(""); err != nil {
		_ = resolver.Shutdown()
		return err
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	<-ctx.Done()

	return resolver.Shutdown()
}

// zoneEntries collects a repeated flag, as a flag.Value because this binary
// has no cobra.
type zoneEntries []string

func (z *zoneEntries) String() string {
	return strings.Join(*z, ",")
}

func (z *zoneEntries) Set(value string) error {
	*z = append(*z, value)
	return nil
}

func (z *zoneEntries) parse() (map[string]string, error) {
	if len(*z) == 0 {
		return nil, fmt.Errorf(errNoZone, errZoneMissing)
	}

	zone := make(map[string]string, len(*z))

	for _, entry := range *z {
		name, address, found := strings.Cut(entry, "=")
		if !found || name == "" || address == "" {
			return nil, fmt.Errorf(errZoneEntry, errZoneFormat, entry)
		}
		zone[name] = address
	}

	return zone, nil
}
