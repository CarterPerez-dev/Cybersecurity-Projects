// ©AngelaMos | 2026
// client.go

package swpc

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"golang.org/x/time/rate"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/httpx"
)

const (
	defaultSWPCBaseURL = "https://services.swpc.noaa.gov"
	pathPlasma         = "/json/rtsw/rtsw_wind_1m.json"
	pathMag            = "/json/rtsw/rtsw_mag_1m.json"
	pathKp             = "/products/noaa-planetary-k-index.json"
	pathXray           = "/json/goes/primary/xrays-1-day.json"
	pathAlerts         = "/products/alerts.json"
	defaultSWPCRate    = 200 * time.Millisecond
	defaultSWPCBurst   = 5
	defaultSWPCBudget  = 5
	defaultSWPCBreaker = 60 * time.Second
	rtswWindowRows     = 180
)

type ClientConfig struct {
	BaseURL string
}

type Client struct {
	hx *httpx.Client
}

func NewClient(cfg ClientConfig) *Client {
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultSWPCBaseURL
	}
	return &Client{
		hx: httpx.New(httpx.Config{
			Name:                     "swpc",
			BaseURL:                  cfg.BaseURL,
			Rate:                     rate.Every(defaultSWPCRate),
			Burst:                    defaultSWPCBurst,
			ConsecutiveFailureBudget: defaultSWPCBudget,
			BreakerTimeout:           defaultSWPCBreaker,
		}),
	}
}

type PlasmaTick struct {
	TimeTag     time.Time
	Density     string
	Speed       string
	Temperature string
}

type MagTick struct {
	TimeTag time.Time
	BxGSM   string
	ByGSM   string
	BzGSM   string
	LonGSM  string
	LatGSM  string
	Bt      string
}

type KpTick struct {
	TimeTag      time.Time
	Kp           float64
	ARunning     int
	StationCount int
}

type XrayTick struct {
	TimeTag      time.Time
	Satellite    int
	Flux         float64
	ObservedFlux float64
	Energy       string
}

type AlertItem struct {
	ProductID     string
	IssueDatetime time.Time
	Message       string
}

type rtswWindRow struct {
	TimeTag           string   `json:"time_tag"`
	Active            bool     `json:"active"`
	ProtonSpeed       *float64 `json:"proton_speed"`
	ProtonDensity     *float64 `json:"proton_density"`
	ProtonTemperature *float64 `json:"proton_temperature"`
}

type rtswMagRow struct {
	TimeTag  string   `json:"time_tag"`
	Active   bool     `json:"active"`
	Bt       *float64 `json:"bt"`
	BxGSM    *float64 `json:"bx_gsm"`
	ByGSM    *float64 `json:"by_gsm"`
	BzGSM    *float64 `json:"bz_gsm"`
	ThetaGSM *float64 `json:"theta_gsm"`
	PhiGSM   *float64 `json:"phi_gsm"`
}

func (c *Client) FetchPlasma(ctx context.Context) ([]PlasmaTick, error) {
	var raw []rtswWindRow
	if err := c.hx.GetJSON(ctx, pathPlasma, nil, &raw); err != nil {
		return nil, fmt.Errorf("fetch rtsw wind %s: %w", pathPlasma, err)
	}
	window, err := activeWindow(
		raw,
		pathPlasma,
		func(r rtswWindRow) bool { return r.Active },
	)
	if err != nil {
		return nil, err
	}
	out := make([]PlasmaTick, 0, len(window))
	for _, r := range window {
		ts, err := ParseTime(r.TimeTag)
		if err != nil || r.ProtonSpeed == nil {
			continue
		}
		out = append(out, PlasmaTick{
			TimeTag:     ts,
			Density:     formatSWPCFloat(r.ProtonDensity),
			Speed:       formatSWPCFloat(r.ProtonSpeed),
			Temperature: formatSWPCFloat(r.ProtonTemperature),
		})
	}
	reverseInPlace(out)
	return out, nil
}

func (c *Client) FetchMag(ctx context.Context) ([]MagTick, error) {
	var raw []rtswMagRow
	if err := c.hx.GetJSON(ctx, pathMag, nil, &raw); err != nil {
		return nil, fmt.Errorf("fetch rtsw mag %s: %w", pathMag, err)
	}
	window, err := activeWindow(
		raw,
		pathMag,
		func(r rtswMagRow) bool { return r.Active },
	)
	if err != nil {
		return nil, err
	}
	out := make([]MagTick, 0, len(window))
	for _, r := range window {
		ts, err := ParseTime(r.TimeTag)
		if err != nil || r.BzGSM == nil {
			continue
		}
		out = append(out, MagTick{
			TimeTag: ts,
			BxGSM:   formatSWPCFloat(r.BxGSM),
			ByGSM:   formatSWPCFloat(r.ByGSM),
			BzGSM:   formatSWPCFloat(r.BzGSM),
			LonGSM:  formatSWPCFloat(r.PhiGSM),
			LatGSM:  formatSWPCFloat(r.ThetaGSM),
			Bt:      formatSWPCFloat(r.Bt),
		})
	}
	reverseInPlace(out)
	return out, nil
}

func activeWindow[T any](
	rows []T,
	path string,
	isActive func(T) bool,
) ([]T, error) {
	out := make([]T, 0, rtswWindowRows)
	for _, r := range rows {
		if !isActive(r) {
			continue
		}
		out = append(out, r)
		if len(out) == rtswWindowRows {
			break
		}
	}
	if len(rows) > 0 && len(out) == 0 {
		return nil, fmt.Errorf(
			"rtsw %s: %d rows but none from the active spacecraft",
			path,
			len(rows),
		)
	}
	return out, nil
}

func reverseInPlace[T any](rows []T) {
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
}

func formatSWPCFloat(v *float64) string {
	if v == nil {
		return ""
	}
	return strconv.FormatFloat(*v, 'f', -1, 64)
}

type rawKp struct {
	TimeTag      string  `json:"time_tag"`
	Kp           float64 `json:"Kp"`
	ARunning     int     `json:"a_running"`
	StationCount int     `json:"station_count"`
}

func (c *Client) FetchKp(ctx context.Context) ([]KpTick, error) {
	var rows []rawKp
	if err := c.hx.GetJSON(ctx, pathKp, nil, &rows); err != nil {
		return nil, fmt.Errorf("fetch kp: %w", err)
	}
	out := make([]KpTick, 0, len(rows))
	for _, r := range rows {
		ts, _ := ParseTime(r.TimeTag)
		out = append(out, KpTick{
			TimeTag:      ts,
			Kp:           r.Kp,
			ARunning:     r.ARunning,
			StationCount: r.StationCount,
		})
	}
	return out, nil
}

type rawXray struct {
	TimeTag      string  `json:"time_tag"`
	Satellite    int     `json:"satellite"`
	Flux         float64 `json:"flux"`
	ObservedFlux float64 `json:"observed_flux"`
	Energy       string  `json:"energy"`
}

func (c *Client) FetchXray(ctx context.Context) ([]XrayTick, error) {
	var rows []rawXray
	if err := c.hx.GetJSON(ctx, pathXray, nil, &rows); err != nil {
		return nil, fmt.Errorf("fetch xray: %w", err)
	}
	out := make([]XrayTick, 0, len(rows))
	for _, r := range rows {
		ts, _ := ParseTime(r.TimeTag)
		out = append(out, XrayTick{
			TimeTag:      ts,
			Satellite:    r.Satellite,
			Flux:         r.Flux,
			ObservedFlux: r.ObservedFlux,
			Energy:       r.Energy,
		})
	}
	return out, nil
}

type rawAlert struct {
	ProductID     string `json:"product_id"`
	IssueDatetime string `json:"issue_datetime"`
	Message       string `json:"message"`
}

func (c *Client) FetchAlerts(ctx context.Context) ([]AlertItem, error) {
	var rows []rawAlert
	if err := c.hx.GetJSON(ctx, pathAlerts, nil, &rows); err != nil {
		return nil, fmt.Errorf("fetch alerts: %w", err)
	}
	out := make([]AlertItem, 0, len(rows))
	for _, r := range rows {
		ts, _ := ParseTime(r.IssueDatetime)
		out = append(out, AlertItem{
			ProductID:     r.ProductID,
			IssueDatetime: ts,
			Message:       r.Message,
		})
	}
	return out, nil
}

var swpcTimeFormats = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.000",
	"2006-01-02 15:04:05",
}

func ParseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty swpc time")
	}
	for _, f := range swpcTimeFormats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized swpc time: %q", s)
}
