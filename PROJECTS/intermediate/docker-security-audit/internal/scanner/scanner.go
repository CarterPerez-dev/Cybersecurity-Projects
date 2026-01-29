/*
AngelaMos | 2026
scanner.go
*/

package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"github.com/CarterPerez-dev/docksec/internal/analyzer"
	"github.com/CarterPerez-dev/docksec/internal/config"
	"github.com/CarterPerez-dev/docksec/internal/docker"
	"github.com/CarterPerez-dev/docksec/internal/finding"
	"github.com/CarterPerez-dev/docksec/internal/report"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

type Scanner struct {
	cfg      *config.Config
	client   *docker.Client
	logger   *slog.Logger
	limiter  *rate.Limiter
	reporter report.Reporter
}

func New(cfg *config.Config) (*Scanner, error) {
	client, err := docker.NewClient()
	if err != nil {
		return nil, fmt.Errorf("creating docker client: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: getLogLevel(cfg),
	}))

	reporter, err := report.NewReporter(cfg.Output, cfg.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("creating reporter: %w", err)
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = runtime.NumCPU() * 4
	}
	if workers > config.MaxWorkers {
		workers = config.MaxWorkers
	}

	limiter := rate.NewLimiter(
		rate.Limit(config.RateLimitPerSecond),
		config.RateLimitBurst,
	)

	return &Scanner{
		cfg:      cfg,
		client:   client,
		logger:   logger,
		limiter:  limiter,
		reporter: reporter,
	}, nil
}

func (s *Scanner) Close() error {
	return s.client.Close()
}

func (s *Scanner) Run(ctx context.Context) error {
	if err := s.client.Ping(ctx); err != nil {
		return fmt.Errorf("docker daemon not accessible: %w", err)
	}

	s.logger.Info("starting security scan")

	analyzers := s.buildAnalyzers()
	if len(analyzers) == 0 {
		return fmt.Errorf("no analyzers configured")
	}

	findings, err := s.runAnalyzers(ctx, analyzers)
	if err != nil {
		return err
	}

	findings = s.filterFindings(findings)

	if err := s.reporter.Report(findings); err != nil {
		return fmt.Errorf("generating report: %w", err)
	}

	return s.checkFailThreshold(findings)
}

func (s *Scanner) buildAnalyzers() []analyzer.Analyzer {
	var analyzers []analyzer.Analyzer

	if s.cfg.ShouldScanContainers() {
		analyzers = append(analyzers, analyzer.NewContainerAnalyzer(s.client))
	}

	if s.cfg.ShouldScanDaemon() {
		analyzers = append(analyzers, analyzer.NewDaemonAnalyzer(s.client))
	}

	if s.cfg.ShouldScanImages() {
		analyzers = append(analyzers, analyzer.NewImageAnalyzer(s.client))
	}

	for _, file := range s.cfg.Files {
		if isDockerfile(file) {
			analyzers = append(
				analyzers,
				analyzer.NewDockerfileAnalyzer(file),
			)
		} else if isComposeFile(file) {
			analyzers = append(analyzers, analyzer.NewComposeAnalyzer(file))
		}
	}

	return analyzers
}

func (s *Scanner) runAnalyzers(
	ctx context.Context,
	analyzers []analyzer.Analyzer,
) (finding.Collection, error) {
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(s.cfg.Workers)

	results := make(chan finding.Collection, len(analyzers))

	for _, a := range analyzers {
		a := a
		g.Go(func() error {
			if err := s.limiter.Wait(ctx); err != nil {
				return err
			}

			s.logger.Debug("running analyzer", "name", a.Name())

			findings, err := a.Analyze(ctx)
			if err != nil {
				s.logger.Warn(
					"analyzer failed",
					"name",
					a.Name(),
					"error",
					err,
				)
				return nil
			}

			results <- findings
			return nil
		})
	}

	go func() {
		_ = g.Wait() // error captured by second Wait() on line 164
		close(results)
	}()

	var allFindings finding.Collection
	for findings := range results {
		allFindings = append(allFindings, findings...)
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return allFindings, nil
}

func (s *Scanner) filterFindings(
	findings finding.Collection,
) finding.Collection {
	var filtered finding.Collection

	for _, f := range findings {
		if len(s.cfg.Severity) > 0 &&
			!s.cfg.ShouldIncludeSeverity(f.Severity) {
			continue
		}

		if len(s.cfg.CISControls) > 0 && !s.matchesCISControl(f) {
			continue
		}

		filtered = append(filtered, f)

		if len(filtered) >= config.MaxTotalFindings {
			s.logger.Warn(
				"maximum total findings reached",
				"limit",
				config.MaxTotalFindings,
			)
			break
		}
	}

	return filtered
}

func (s *Scanner) matchesCISControl(f *finding.Finding) bool {
	if f.CISControl == nil {
		return false
	}
	for _, c := range s.cfg.CISControls {
		if f.CISControl.ID == c {
			return true
		}
	}
	return false
}

func (s *Scanner) checkFailThreshold(findings finding.Collection) error {
	threshold, ok := s.cfg.GetFailOnSeverity()
	if !ok {
		return nil
	}

	if findings.HasSeverityAtOrAbove(threshold) {
		return &ExitError{
			Code: 1,
			Message: fmt.Sprintf(
				"findings at or above %s severity",
				threshold,
			),
		}
	}

	return nil
}

type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string {
	return e.Message
}

func getLogLevel(cfg *config.Config) slog.Level {
	if cfg.Quiet {
		return slog.LevelError
	}
	if cfg.Verbose {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

func isDockerfile(path string) bool {
	return path == "Dockerfile" ||
		len(path) > 11 && path[len(path)-11:] == "/Dockerfile" ||
		len(path) > 11 && path[:11] == "Dockerfile."
}

func isComposeFile(path string) bool {
	return path == "docker-compose.yml" ||
		path == "docker-compose.yaml" ||
		path == "compose.yml" ||
		path == "compose.yaml" ||
		len(path) > 4 &&
			(path[len(path)-4:] == ".yml" || path[len(path)-5:] == ".yaml")
}
