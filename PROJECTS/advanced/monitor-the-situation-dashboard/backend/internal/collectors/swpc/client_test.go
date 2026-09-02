// ©AngelaMos | 2026
// client_test.go

package swpc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/collectors/swpc"
)

func newFakeServer(t *testing.T, route, fixture string) *httptest.Server {
	t.Helper()
	body, err := os.ReadFile("testdata/" + fixture)
	require.NoError(t, err)
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.URL.Path, route) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}),
	)
	t.Cleanup(srv.Close)
	return srv
}

func TestClient_FetchPlasmaDecodesObjectArray(t *testing.T) {
	srv := newFakeServer(t, "rtsw_wind_1m", "plasma.json")
	c := swpc.NewClient(swpc.ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rows, err := c.FetchPlasma(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.False(t, rows[0].TimeTag.IsZero())
	require.NotEmpty(t, rows[0].Density)
	require.NotEmpty(t, rows[0].Speed)
	require.Equal(t, "391.3", rows[len(rows)-1].Speed)
	require.Equal(t, "2.09", rows[len(rows)-1].Density)
	require.NotEqual(
		t,
		"391.71",
		rows[len(rows)-1].Speed,
		"must not read the inactive ACE spacecraft",
	)
}

func TestClient_FetchPlasmaIgnoresInactiveSpacecraft(t *testing.T) {
	srv := newFakeServer(t, "rtsw_wind_1m", "plasma.json")
	c := swpc.NewClient(swpc.ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rows, err := c.FetchPlasma(ctx)
	require.NoError(t, err)
	for _, r := range rows {
		require.NotEqual(t, "391.71", r.Speed)
		require.NotEqual(t, "396.68", r.Speed)
	}
}

func TestClient_FetchPlasmaErrorsWhenNoActiveSpacecraft(t *testing.T) {
	srv := newFakeServer(t, "rtsw_wind_1m", "plasma_inactive.json")
	c := swpc.NewClient(swpc.ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := c.FetchPlasma(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "active spacecraft")
}

func TestClient_FetchPlasmaReturnsAscendingSoLastRowIsNewest(t *testing.T) {
	srv := newFakeServer(t, "rtsw_wind_1m", "plasma.json")
	c := swpc.NewClient(swpc.ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rows, err := c.FetchPlasma(ctx)
	require.NoError(t, err)
	require.Greater(t, len(rows), 1)
	for i := 1; i < len(rows); i++ {
		require.True(
			t,
			rows[i].TimeTag.After(rows[i-1].TimeTag),
			"rows must be ascending: index %d is not after %d", i, i-1,
		)
	}
}

func TestClient_FetchMagDecodesObjectArray(t *testing.T) {
	srv := newFakeServer(t, "rtsw_mag_1m", "mag.json")
	c := swpc.NewClient(swpc.ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rows, err := c.FetchMag(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.Equal(t, "1.32", rows[len(rows)-1].BzGSM)
	require.Equal(t, "5.56", rows[len(rows)-1].Bt)
	require.Equal(t, "316.47", rows[len(rows)-1].LonGSM)
	require.Equal(t, "13.64", rows[len(rows)-1].LatGSM)
	require.NotEqual(
		t,
		"-1.07",
		rows[len(rows)-1].BzGSM,
		"must not read the inactive ACE spacecraft",
	)
}

func TestClient_FetchMagReturnsAscendingSoLastRowIsNewest(t *testing.T) {
	srv := newFakeServer(t, "rtsw_mag_1m", "mag.json")
	c := swpc.NewClient(swpc.ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rows, err := c.FetchMag(ctx)
	require.NoError(t, err)
	require.Greater(t, len(rows), 1)
	for i := 1; i < len(rows); i++ {
		require.True(
			t,
			rows[i].TimeTag.After(rows[i-1].TimeTag),
			"rows must be ascending: index %d is not after %d", i, i-1,
		)
	}
}

func TestClient_FetchKpDecodesObjectArray(t *testing.T) {
	srv := newFakeServer(t, "noaa-planetary-k-index", "kp.json")
	c := swpc.NewClient(swpc.ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rows, err := c.FetchKp(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(rows), 1)
	require.False(t, rows[0].TimeTag.IsZero())
	require.GreaterOrEqual(t, rows[0].Kp, 0.0)
}

func TestClient_FetchXrayDecodesObjectArray(t *testing.T) {
	srv := newFakeServer(t, "xrays-1-day", "xray.json")
	c := swpc.NewClient(swpc.ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rows, err := c.FetchXray(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(rows), 1)
	require.False(t, rows[0].TimeTag.IsZero())
	require.Greater(t, rows[0].Flux, 0.0)
}

func TestClient_FetchAlertsDecodes(t *testing.T) {
	srv := newFakeServer(t, "alerts.json", "alerts.json")
	c := swpc.NewClient(swpc.ClientConfig{BaseURL: srv.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rows, err := c.FetchAlerts(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(rows), 1)
	require.False(t, rows[0].IssueDatetime.IsZero())
	require.NotEmpty(t, rows[0].ProductID)
	require.NotEmpty(t, rows[0].Message)
}

func TestParseSWPCTime_AcceptsAllKnownFormats(t *testing.T) {
	cases := []string{
		"2026-05-02 08:20:00.000",
		"2026-04-25T00:00:00",
		"2026-05-01T08:24:00Z",
		"2026-05-01 15:50:32.247",
	}
	for _, s := range cases {
		got, err := swpc.ParseTime(s)
		require.NoError(t, err, "input %q", s)
		require.False(t, got.IsZero())
	}
}
