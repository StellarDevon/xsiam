package etl

import (
	"fmt"
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// GeoRecord holds the fields extracted from a MaxMind GeoLite2 database lookup.
type GeoRecord struct {
	Country string // ISO 3166-1 alpha-2 country code (e.g. "US")
	City    string // City name in English (may be empty)
	ASN     uint   // Autonomous System Number
	ASNOrg  string // AS organisation name
}

// GeoIPDB wraps a MaxMind GeoLite2 mmdb reader.
// Use OpenGeoIPDB to construct; call Close when done.
// All methods are safe for concurrent use.
type GeoIPDB struct {
	city *maxminddb.Reader // GeoLite2-City.mmdb
	asn  *maxminddb.Reader // GeoLite2-ASN.mmdb (optional, may be nil)
}

// OpenGeoIPDB opens the city mmdb at cityPath and, if asnPath is non-empty,
// also opens the ASN database.  Returns an error if cityPath cannot be opened.
func OpenGeoIPDB(cityPath, asnPath string) (*GeoIPDB, error) {
	if cityPath == "" {
		return nil, fmt.Errorf("geoip: city database path is required")
	}
	city, err := maxminddb.Open(cityPath)
	if err != nil {
		return nil, fmt.Errorf("geoip: open city db %q: %w", cityPath, err)
	}
	g := &GeoIPDB{city: city}
	if asnPath != "" {
		asn, err := maxminddb.Open(asnPath)
		if err != nil {
			// Non-fatal: ASN enrichment simply won't be available.
			_ = city.Close()
			return nil, fmt.Errorf("geoip: open asn db %q: %w", asnPath, err)
		}
		g.asn = asn
	}
	return g, nil
}

// Lookup queries the city (and optional ASN) database for ip.
// Returns an empty GeoRecord if ip is invalid or not found.
func (g *GeoIPDB) Lookup(ip string) GeoRecord {
	if g == nil {
		return GeoRecord{}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return GeoRecord{}
	}

	var rec GeoRecord

	// ── City lookup ──────────────────────────────────────────────────────────
	var cityRecord struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
	}
	if err := g.city.Lookup(parsed, &cityRecord); err == nil {
		rec.Country = cityRecord.Country.ISOCode
		if name, ok := cityRecord.City.Names["en"]; ok {
			rec.City = name
		}
	}

	// ── ASN lookup ───────────────────────────────────────────────────────────
	if g.asn != nil {
		var asnRecord struct {
			ASNumber uint   `maxminddb:"autonomous_system_number"`
			ASOrg    string `maxminddb:"autonomous_system_organization"`
		}
		if err := g.asn.Lookup(parsed, &asnRecord); err == nil {
			rec.ASN = asnRecord.ASNumber
			rec.ASNOrg = asnRecord.ASOrg
		}
	}

	return rec
}

// Close releases the database file handles.
func (g *GeoIPDB) Close() {
	if g == nil {
		return
	}
	if g.city != nil {
		_ = g.city.Close()
	}
	if g.asn != nil {
		_ = g.asn.Close()
	}
}
