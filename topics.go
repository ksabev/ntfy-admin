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
// line of description), one file per server: DATA_DIR/notes/<server>.json.
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

func newTopicStore(path string, writable bool) *topicStore {
	s := &topicStore{path: path, notes: map[string]topicNote{}, writable: writable}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &s.notes); err != nil {
			slog.Warn("topic notes unreadable, starting empty", "file", path, "err", err)
			s.notes = map[string]topicNote{}
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		slog.Warn("cannot read topic notes", "file", path, "err", err)
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
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
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
