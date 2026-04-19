/*
©AngelaMos | 2026
lookup.go

GeoIP resolution using MaxMind GeoLite2 database

Resolves IP addresses to geographic location, ASN, and organization.
Returns a zero-value GeoInfo gracefully when the database file is
missing, allowing the system to operate without a MaxMind account
during local development.
*/

package geo

import (
	"fmt"
	"net"

	"github.com/oschwald/maxminddb-golang"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

type mmdbRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Traits struct {
		AutonomousSystemNumber       int    `maxminddb:"autonomous_system_number"`
		AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	} `maxminddb:"traits"`
}

type Lookup struct {
	reader *maxminddb.Reader
}

func NewLookup(dbPath string) (*Lookup, error) {
	reader, _ := maxminddb.Open(dbPath)
	return &Lookup{reader: reader}, nil
}

func (l *Lookup) Resolve(
	ip string,
) (*types.GeoInfo, error) {
	if l.reader == nil {
		return &types.GeoInfo{}, nil
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid ip: %s", ip)
	}

	if parsed.IsLoopback() || parsed.IsPrivate() {
		return &types.GeoInfo{}, nil
	}

	var record mmdbRecord
	err := l.reader.Lookup(parsed, &record)
	if err != nil {
		return nil, fmt.Errorf("geoip lookup: %w", err)
	}

	return &types.GeoInfo{
		CountryCode: record.Country.ISOCode,
		Country:     record.Country.Names["en"],
		City:        record.City.Names["en"],
		Latitude:    record.Location.Latitude,
		Longitude:   record.Location.Longitude,
		ASN:         record.Traits.AutonomousSystemNumber,
		Org:         record.Traits.AutonomousSystemOrganization,
	}, nil
}

func (l *Lookup) Close() error {
	if l.reader != nil {
		return l.reader.Close()
	}
	return nil
}
