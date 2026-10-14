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

// serveResolver runs khaos's chaos resolver as a range service.
//
// It is the SAME `internal/dnsrv` package khaos runs outside the range, behind a
// different entry point, and that matters for what the range proves. If the
// range ran a separate implementation, every DNS experiment the gate asserts
// would be asserting something an operator's khaos never executes.
//
// Outside the range khaos imports its own binary as a one-layer image, because
// an operator's khaos has no source tree to build from. In here the image
// already exists, so the resolver is an ordinary compose service with the labels
// khaos matches on, and khaos finds it exactly as it finds one it started
// itself.
//
// It does not go through roleHandler, because it is the one role that is not an
// HTTP service: it binds UDP and TCP on 53 and its control surface separately.
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

	// From the ENVIRONMENT, for the measured reason in resolverArgs: a command
	// line is world-readable in the host's process table and this is a secret.
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

// zoneEntries collects a repeated flag. It is a flag.Value rather than a
// StringArray because this binary has no cobra, and the repetition matters: a
// resolver with one zone entry has no control name to confirm against.
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
