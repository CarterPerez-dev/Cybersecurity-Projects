// ©AngelaMos | 2026
// ai_notes_test.go

package store

import "testing"

func insertTestCluster(t *testing.T, s *Store, id int64, key string) {
	t.Helper()
	_, err := s.DB().Exec(
		`INSERT INTO clusters (id, cluster_key, first_seen, last_seen, size) VALUES (?, ?, 0, 0, 1)`,
		id, key,
	)
	if err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
}

func TestAINoteRoundTrip(t *testing.T) {
	s := openTemp(t)
	insertTestCluster(t, s, 1, "k1")

	note := AINote{
		ClusterID: 1, Provider: "qwen",
		Summary: "s", Why: "w", AnglesJSON: `["a","b"]`, Format: "blog", CreatedAt: 100,
	}
	if err := s.InsertAINote(note); err != nil {
		t.Fatalf("InsertAINote: %v", err)
	}

	ok, err := s.AINoteExists(1, "qwen")
	if err != nil || !ok {
		t.Fatalf("AINoteExists(1,qwen) = %v, %v; want true", ok, err)
	}
	if ok, _ := s.AINoteExists(1, "openai"); ok {
		t.Error("AINoteExists(1,openai) = true, want false")
	}
	if ok, _ := s.AINoteExists(2, "qwen"); ok {
		t.Error("AINoteExists(2,qwen) = true, want false")
	}

	notes, err := s.AINotesForCluster(1)
	if err != nil || len(notes) != 1 {
		t.Fatalf("AINotesForCluster = %v, %v; want 1 note", notes, err)
	}
	if notes[0].Summary != "s" || notes[0].Format != "blog" || notes[0].AnglesJSON != `["a","b"]` {
		t.Errorf("note = %+v", notes[0])
	}
}

func TestAINoteUpsertOverwrites(t *testing.T) {
	s := openTemp(t)
	insertTestCluster(t, s, 1, "k1")

	if err := s.InsertAINote(AINote{ClusterID: 1, Provider: "qwen", Summary: "first", AnglesJSON: "[]", Format: "blog", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertAINote(AINote{ClusterID: 1, Provider: "qwen", Summary: "second", AnglesJSON: "[]", Format: "video", CreatedAt: 2}); err != nil {
		t.Fatal(err)
	}
	notes, err := s.AINotesForCluster(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 {
		t.Fatalf("got %d notes, want 1 (upsert should overwrite)", len(notes))
	}
	if notes[0].Summary != "second" || notes[0].Format != "video" || notes[0].CreatedAt != 2 {
		t.Errorf("upsert did not overwrite: %+v", notes[0])
	}
}

func TestLatestAINotesNewestPerCluster(t *testing.T) {
	s := openTemp(t)
	insertTestCluster(t, s, 1, "k1")
	insertTestCluster(t, s, 2, "k2")

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.InsertAINote(AINote{ClusterID: 1, Provider: "qwen", Summary: "old", AnglesJSON: "[]", Format: "blog", CreatedAt: 10}))
	must(s.InsertAINote(AINote{ClusterID: 1, Provider: "anthropic", Summary: "new", AnglesJSON: "[]", Format: "video", CreatedAt: 20}))
	must(s.InsertAINote(AINote{ClusterID: 2, Provider: "qwen", Summary: "two", AnglesJSON: "[]", Format: "blog", CreatedAt: 5}))

	notes, err := s.LatestAINotes()
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 2 {
		t.Fatalf("got %d clusters, want 2", len(notes))
	}
	if notes[1].Summary != "new" {
		t.Errorf("cluster 1 latest = %q, want new (highest created_at)", notes[1].Summary)
	}
	if notes[2].Summary != "two" {
		t.Errorf("cluster 2 = %q, want two", notes[2].Summary)
	}
}

func TestAINoteForeignKeyRejectsOrphan(t *testing.T) {
	s := openTemp(t)
	err := s.InsertAINote(AINote{ClusterID: 99, Provider: "qwen", AnglesJSON: "[]", Format: "blog", CreatedAt: 1})
	if err == nil {
		t.Error("insert for a nonexistent cluster should be rejected by the foreign key")
	}
}

func TestAINoteCascadesOnClusterDelete(t *testing.T) {
	s := openTemp(t)
	insertTestCluster(t, s, 1, "k1")
	if err := s.InsertAINote(AINote{ClusterID: 1, Provider: "qwen", AnglesJSON: "[]", Format: "blog", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`DELETE FROM clusters WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	notes, err := s.AINotesForCluster(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Errorf("notes should cascade on cluster delete, %d remain", len(notes))
	}
}
