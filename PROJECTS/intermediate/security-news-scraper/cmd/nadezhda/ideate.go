// ©AngelaMos | 2026
// ideate.go

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/nadezhda/internal/ai"
	"github.com/CarterPerez-dev/nadezhda/internal/rank"
	"github.com/CarterPerez-dev/nadezhda/internal/setup"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const defaultIdeateTop = 10

var (
	ideateTop      int
	ideateSince    string
	ideateProvider string
	ideateForce    bool
)

var ideateCmd = &cobra.Command{
	Use:   "ideate",
	Short: "Generate content angles from ranked clusters via an AI provider (opt-in)",
	RunE:  runIdeate,
}

func init() {
	ideateCmd.Flags().IntVar(&ideateTop, "top", defaultIdeateTop, "ideate the top N ranked clusters")
	ideateCmd.Flags().StringVar(&ideateSince, "since", "", "only clusters active within this window (e.g. 24h, 168h)")
	ideateCmd.Flags().StringVar(&ideateProvider, "provider", "", "override the configured provider: qwen|openai|anthropic|gemini")
	ideateCmd.Flags().BoolVar(&ideateForce, "force", false, "re-ideate clusters that already have a note for this provider")
	rootCmd.AddCommand(ideateCmd)
}

func runIdeate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	aiCfg := cfg.AI
	if ideateProvider != "" {
		aiCfg.Provider = ideateProvider
		aiCfg.Enabled = true
	}
	if !aiCfg.Enabled {
		if !isInteractive(cmd) {
			return fmt.Errorf("AI is not set up — run `nadezhda ai` to configure a provider")
		}
		fmt.Fprintln(cmd.OutOrStdout(), "AI is not set up yet — let's fix that.")
		if err := setup.Run(cmd.InOrStdin(), cmd.OutOrStdout()); err != nil {
			return err
		}
		cfg, err = loadConfig()
		if err != nil {
			return err
		}
		aiCfg = cfg.AI
		if !aiCfg.Enabled {
			return fmt.Errorf("AI still not configured after setup")
		}
		if aiCfg.Provider == ai.ProviderQwen && !setup.OllamaReachable(aiCfg.Qwen.BaseURL) {
			fmt.Fprintln(cmd.OutOrStdout(), "Ollama isn't reachable yet — finish the steps above, then run: nadezhda ideate")
			return nil
		}
	}
	provider, err := ai.Factory(aiCfg)
	if err != nil {
		return err
	}

	now := time.Now()
	var since int64
	if ideateSince != "" {
		d, err := time.ParseDuration(ideateSince)
		if err != nil {
			return fmt.Errorf("invalid --since %q: %w", ideateSince, err)
		}
		since = now.Add(-d).Unix()
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	clusters, err := st.DigestClusters(since)
	if err != nil {
		return err
	}
	scored := rank.Rank(clusters, cfg.Rank, cfg.Watchlist, now)
	if ideateTop > 0 && ideateTop < len(scored) {
		scored = scored[:ideateTop]
	}

	out := cmd.OutOrStdout()
	ctx := cmd.Context()
	var generated, skipped, refused, failed int

	for _, s := range scored {
		cid := s.Cluster.ClusterID
		if !ideateForce {
			exists, err := st.AINoteExists(cid, provider.Name())
			if err != nil {
				return err
			}
			if exists {
				skipped++
				fmt.Fprintf(out, "skip cluster %d (already ideated by %s; use --force)\n", cid, provider.Name())
				continue
			}
		}

		res, err := provider.Generate(ctx, ai.RequestFromCluster(s.Cluster))
		if err != nil {
			if errors.Is(err, ai.ErrRefused) {
				refused++
				fmt.Fprintf(out, "refused cluster %d (provider declined); skipping\n", cid)
			} else {
				failed++
				fmt.Fprintf(out, "warn cluster %d: %v\n", cid, err)
			}
			continue
		}

		angles, err := json.Marshal(res.Angles)
		if err != nil {
			return err
		}
		note := store.AINote{
			ClusterID:  cid,
			Provider:   provider.Name(),
			Summary:    res.Summary,
			Why:        res.Why,
			AnglesJSON: string(angles),
			Format:     res.Format,
			CreatedAt:  time.Now().Unix(),
		}
		if err := st.InsertAINote(note); err != nil {
			return err
		}
		generated++
		printIdeation(out, s, res)
	}

	fmt.Fprintf(out, "\nideated %d, skipped %d, refused %d, failed %d (provider: %s)\n", generated, skipped, refused, failed, provider.Name())
	if generated == 0 && failed > 0 {
		return fmt.Errorf("all %d ideation attempts failed", failed)
	}
	return nil
}

func printIdeation(out io.Writer, s rank.Scored, res ai.IdeationResult) {
	fmt.Fprintf(out, "\n=== cluster %d  score %.2f  [%s] ===\n", s.Cluster.ClusterID, s.Score, res.Format)
	fmt.Fprintf(out, "%s\n\n", clusterHeadline(s.Cluster))
	fmt.Fprintf(out, "summary: %s\n\n", res.Summary)
	fmt.Fprintf(out, "why: %s\n\n", res.Why)
	fmt.Fprintln(out, "angles:")
	for i, a := range res.Angles {
		fmt.Fprintf(out, "  %d. %s\n", i+1, a)
	}
}

func clusterHeadline(c store.DigestCluster) string {
	for _, a := range c.Articles {
		if a.Title != "" {
			return a.Title
		}
	}
	return "(untitled cluster)"
}
