package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// ntfy has no topic registry: topics exist the moment someone publishes. The
// panel keeps optional notes per topic (a display name for the phone app and a
// line of description) in DATA_DIR/topics.json. No secrets in there.
type topicNote struct {
	Display string `json:"display,omitempty" yaml:"display,omitempty"`
	About   string `json:"about,omitempty" yaml:"about,omitempty"`
}

type topicStore struct {
	mu       sync.Mutex
	path     string
	notes    map[string]topicNote
	writable bool
}

func newTopicStore(dir string) *topicStore {
	s := &topicStore{path: filepath.Join(dir, "topics.json"), notes: map[string]topicNote{}}
	data, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &s.notes); err != nil {
			slog.Warn("topics.json unreadable, starting empty", "err", err)
			s.notes = map[string]topicNote{}
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		slog.Warn("cannot read topics.json", "err", err)
	}
	// probe writability once, so the UI can say so instead of failing on save
	if err := os.MkdirAll(dir, 0o750); err == nil {
		probe := filepath.Join(dir, ".write-test")
		if f, err := os.Create(probe); err == nil {
			f.Close()
			os.Remove(probe)
			s.writable = true
		}
	}
	if !s.writable {
		slog.Warn("data dir not writable; topic notes are read-only", "dir", dir)
	}
	return s
}

func (s *topicStore) all() map[string]topicNote {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]topicNote, len(s.notes))
	for k, v := range s.notes {
		out[k] = v
	}
	return out
}

func (s *topicStore) set(topic string, n topicNote) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.writable {
		return errors.New("data dir is not writable (mount a volume at NTFY_ADMIN_DATA_DIR)")
	}
	s.notes[topic] = n
	return s.saveLocked()
}

func (s *topicStore) remove(topic string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.writable {
		return errors.New("data dir is not writable (mount a volume at NTFY_ADMIN_DATA_DIR)")
	}
	delete(s.notes, topic)
	return s.saveLocked()
}

func (s *topicStore) saveLocked() error {
	data, err := json.MarshalIndent(s.notes, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
