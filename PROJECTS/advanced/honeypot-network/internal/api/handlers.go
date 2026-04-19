/*
©AngelaMos | 2026
handlers.go

REST endpoint handlers for the hive dashboard API

Each handler reads from the persistent store, formats the response
as JSON, and returns it with appropriate HTTP status codes.
Pagination is supported on list endpoints via limit and offset
query parameters. Export endpoints stream STIX bundles and
firewall blocklists as downloadable files.
*/

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/CarterPerez-dev/hive/internal/intel"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type apiResponse struct {
	Data interface{} `json:"data"`
}

type paginatedResponse struct {
	Data   interface{} `json:"data"`
	Total  int64       `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

type apiError struct {
	Error string `json:"error"`
}

type overviewStats struct {
	TotalEvents     int64            `json:"total_events"`
	ActiveSessions  int              `json:"active_sessions"`
	EventsByService map[string]int64 `json:"events_by_service"`
}

type credentialStats struct {
	TopUsernames []credentialEntry `json:"top_usernames"`
	TopPasswords []credentialEntry `json:"top_passwords"`
	TopPairs     []credentialPair  `json:"top_pairs"`
}

type credentialEntry struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type credentialPair struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Count    int64  `json:"count"`
}

type techniqueInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

type heatmapEntry struct {
	TechniqueID string `json:"technique_id"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	Count       int64  `json:"count"`
}

type sensorInfo struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	Region    string    `json:"region"`
	Services  []string  `json:"services"`
	StartedAt time.Time `json:"started_at"`
	Status    string    `json:"status"`
}

func (s *Server) writeJSON(
	w http.ResponseWriter,
	status int,
	data interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) writeError(
	w http.ResponseWriter, status int, msg string,
) {
	s.writeJSON(w, status, apiError{Error: msg})
}

func (s *Server) handleHealth(
	w http.ResponseWriter, _ *http.Request,
) {
	s.writeJSON(w, http.StatusOK, apiResponse{
		Data: map[string]interface{}{
			"status":  "ok",
			"version": types.Version,
			"sensor":  s.cfg.Sensor.ID,
		},
	})
}

func (s *Server) handleStatsOverview(
	w http.ResponseWriter, r *http.Request,
) {
	ctx := r.Context()
	since := time.Now().UTC().Add(
		-parseDuration(r),
	)

	totalEvents, err := s.store.TotalCount(ctx)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to count events",
		)
		return
	}

	byService, err := s.store.CountByService(ctx, since)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to count by service",
		)
		return
	}

	serviceMap := make(map[string]int64, len(byService))
	for svc, count := range byService {
		serviceMap[svc.String()] = count
	}

	s.writeJSON(w, http.StatusOK, apiResponse{
		Data: overviewStats{
			TotalEvents:     totalEvents,
			ActiveSessions:  s.tracker.Count(),
			EventsByService: serviceMap,
		},
	})
}

func (s *Server) handleStatsCountries(
	w http.ResponseWriter, r *http.Request,
) {
	ctx := r.Context()
	since := time.Now().UTC().Add(
		-parseDuration(r),
	)

	countries, err := s.store.CountByCountry(ctx, since)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to count by country",
		)
		return
	}

	s.writeJSON(w, http.StatusOK, apiResponse{
		Data: countries,
	})
}

func (s *Server) handleStatsCredentials(
	w http.ResponseWriter, r *http.Request,
) {
	ctx := r.Context()

	usernames, err := s.store.TopUsernames(
		ctx, defaultCredentialTop,
	)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to query usernames",
		)
		return
	}

	passwords, err := s.store.TopPasswords(
		ctx, defaultCredentialTop,
	)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to query passwords",
		)
		return
	}

	pairs, err := s.store.TopPairs(
		ctx, defaultCredentialTop,
	)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to query credential pairs",
		)
		return
	}

	topU := make([]credentialEntry, len(usernames))
	for i, u := range usernames {
		topU[i] = credentialEntry{
			Value: u.Value, Count: u.Count,
		}
	}

	topP := make([]credentialEntry, len(passwords))
	for i, p := range passwords {
		topP[i] = credentialEntry{
			Value: p.Value, Count: p.Count,
		}
	}

	topPairs := make([]credentialPair, len(pairs))
	for i, p := range pairs {
		topPairs[i] = credentialPair{
			Username: p.Username,
			Password: p.Password,
			Count:    p.Count,
		}
	}

	s.writeJSON(w, http.StatusOK, apiResponse{
		Data: credentialStats{
			TopUsernames: topU,
			TopPasswords: topP,
			TopPairs:     topPairs,
		},
	})
}

func (s *Server) handleEvents(
	w http.ResponseWriter, r *http.Request,
) {
	ctx := r.Context()
	limit, offset := parsePagination(r)
	ip := r.URL.Query().Get("ip")

	if ip != "" {
		events, err := s.store.FindByIP(
			ctx, ip, limit, offset,
		)
		if err != nil {
			s.writeError(
				w, http.StatusInternalServerError,
				"failed to query events",
			)
			return
		}
		s.writeJSON(
			w, http.StatusOK,
			apiResponse{Data: events},
		)
		return
	}

	events, err := s.store.RecentEvents(ctx, limit)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to query events",
		)
		return
	}

	s.writeJSON(
		w, http.StatusOK, apiResponse{Data: events},
	)
}

func (s *Server) handleSessions(
	w http.ResponseWriter, r *http.Request,
) {
	ctx := r.Context()
	limit, offset := parsePagination(r)
	service := r.URL.Query().Get("service")

	sessions, total, err := s.store.ListSessions(
		ctx, service, limit, offset,
	)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to query sessions",
		)
		return
	}

	s.writeJSON(w, http.StatusOK, paginatedResponse{
		Data:   sessions,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

func (s *Server) handleSessionByID(
	w http.ResponseWriter, r *http.Request,
) {
	id := chi.URLParam(r, "id")

	sess, err := s.store.GetSession(r.Context(), id)
	if err != nil {
		s.writeError(
			w, http.StatusNotFound, "session not found",
		)
		return
	}

	s.writeJSON(
		w, http.StatusOK, apiResponse{Data: sess},
	)
}

func isValidSessionID(id string) bool {
	if len(id) < 8 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *Server) handleSessionReplay(
	w http.ResponseWriter, r *http.Request,
) {
	id := chi.URLParam(r, "id")

	if !isValidSessionID(id) {
		s.writeError(
			w, http.StatusBadRequest, "invalid session id",
		)
		return
	}

	castPath := filepath.Join(
		s.replayDir, fmt.Sprintf("%s.cast", id),
	)

	data, err := os.ReadFile(castPath)
	if err != nil {
		s.writeError(
			w, http.StatusNotFound, "replay not found",
		)
		return
	}

	w.Header().Set(
		"Content-Type", "application/x-asciicast",
	)
	w.Header().Set(
		"Content-Disposition",
		fmt.Sprintf(
			"inline; filename=\"%s.cast\"", id,
		),
	)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleAttackers(
	w http.ResponseWriter, r *http.Request,
) {
	ctx := r.Context()
	since := time.Now().UTC().Add(
		-parseDuration(r),
	)
	limit, offset := parsePagination(r)

	attackers, err := s.store.TopAttackers(
		ctx, since, limit, offset,
	)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to query attackers",
		)
		return
	}

	s.writeJSON(
		w, http.StatusOK, apiResponse{Data: attackers},
	)
}

func (s *Server) handleAttackerByID(
	w http.ResponseWriter, r *http.Request,
) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		s.writeError(
			w, http.StatusBadRequest,
			"invalid attacker id",
		)
		return
	}

	attacker, err := s.store.GetAttacker(
		r.Context(), id,
	)
	if err != nil {
		s.writeError(
			w, http.StatusNotFound,
			"attacker not found",
		)
		return
	}

	s.writeJSON(
		w, http.StatusOK, apiResponse{Data: attacker},
	)
}

func (s *Server) handleMITRETechniques(
	w http.ResponseWriter, _ *http.Request,
) {
	techniques := s.mitreIdx.All()

	infos := make([]techniqueInfo, len(techniques))
	for i, t := range techniques {
		infos[i] = techniqueInfo{
			ID:     t.ID,
			Name:   t.Name,
			Tactic: t.Tactic,
		}
	}

	s.writeJSON(
		w, http.StatusOK, apiResponse{Data: infos},
	)
}

func (s *Server) handleMITREHeatmap(
	w http.ResponseWriter, r *http.Request,
) {
	ctx := r.Context()
	since := time.Now().UTC().Add(
		-parseDuration(r),
	)

	counts, err := s.store.TechniqueHeatmap(ctx, since)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to query heatmap",
		)
		return
	}

	entries := make([]heatmapEntry, len(counts))
	for i, tc := range counts {
		name := tc.TechniqueID
		if t := s.mitreIdx.Get(tc.TechniqueID); t != nil {
			name = t.Name
		}
		entries[i] = heatmapEntry{
			TechniqueID: tc.TechniqueID,
			Name:        name,
			Tactic:      tc.Tactic,
			Count:       tc.Count,
		}
	}

	s.writeJSON(
		w, http.StatusOK, apiResponse{Data: entries},
	)
}

func (s *Server) handleIOCs(
	w http.ResponseWriter, r *http.Request,
) {
	ctx := r.Context()
	limit, offset := parsePagination(r)

	iocs, total, err := s.store.ListIOCs(
		ctx, limit, offset,
	)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to query iocs",
		)
		return
	}

	s.writeJSON(w, http.StatusOK, paginatedResponse{
		Data:   iocs,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

func (s *Server) handleIOCExportSTIX(
	w http.ResponseWriter, r *http.Request,
) {
	ctx := r.Context()

	iocs, _, err := s.store.ListIOCs(
		ctx, maxPageLimit, 0,
	)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to query iocs",
		)
		return
	}

	bundle, err := intel.GenerateSTIXBundle(iocs)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to generate stix bundle",
		)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(
		"Content-Disposition",
		"attachment; filename=\"hive-iocs.stix.json\"",
	)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

func (s *Server) handleIOCExportBlocklist(
	w http.ResponseWriter, r *http.Request,
) {
	ctx := r.Context()
	format := r.URL.Query().Get("format")
	if format == "" {
		format = intel.FormatPlain
	}

	iocs, _, err := s.store.ListIOCs(
		ctx, maxPageLimit, 0,
	)
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to query iocs",
		)
		return
	}

	blocklist := intel.GenerateBlocklist(iocs, format)

	contentType := "text/plain"
	ext := ".txt"
	if format == intel.FormatCSV {
		contentType = "text/csv"
		ext = ".csv"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set(
		"Content-Disposition",
		fmt.Sprintf(
			"attachment; filename=\"hive-blocklist%s\"",
			ext,
		),
	)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, blocklist)
}

func (s *Server) handleSensors(
	w http.ResponseWriter, _ *http.Request,
) {
	var services []string
	if s.cfg.SSH.Enabled {
		services = append(services, "ssh")
	}
	if s.cfg.HTTP.Enabled {
		services = append(services, "http")
	}
	if s.cfg.FTP.Enabled {
		services = append(services, "ftp")
	}
	if s.cfg.SMB.Enabled {
		services = append(services, "smb")
	}
	if s.cfg.MySQL.Enabled {
		services = append(services, "mysql")
	}
	if s.cfg.Redis.Enabled {
		services = append(services, "redis")
	}

	sensor := sensorInfo{
		ID:        s.cfg.Sensor.ID,
		Hostname:  s.cfg.Sensor.Hostname,
		Region:    s.cfg.Sensor.Region,
		Services:  services,
		StartedAt: s.startedAt,
		Status:    "active",
	}

	s.writeJSON(w, http.StatusOK, apiResponse{
		Data: []sensorInfo{sensor},
	})
}

func parsePagination(r *http.Request) (int, int) {
	limit := defaultPageLimit
	offset := 0

	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	if limit > maxPageLimit {
		limit = maxPageLimit
	}

	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	return limit, offset
}

func parseDuration(r *http.Request) time.Duration {
	v := r.URL.Query().Get("since")
	if v == "" {
		return defaultStatsDuration
	}

	d, err := time.ParseDuration(v)
	if err != nil {
		return defaultStatsDuration
	}

	return d
}
