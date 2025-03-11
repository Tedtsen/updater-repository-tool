package filesemaphore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type SemaphoreName string

type SemaphoreFileDesc struct {
	Filepath string
	Content  string
}

type SemaphoreMap map[SemaphoreName]*SemaphoreFileDesc

type Semaphore struct {
	SemaphoreDir string
	SemaphoreMap SemaphoreMap
}

// Initialize by creating a new directory at semaphoreDir.
func New(semaphoreDir string, semaphoreMap SemaphoreMap) (*Semaphore, error) {
	if err := os.MkdirAll(semaphoreDir, 0700); err != nil {
		return nil, fmt.Errorf("fail to make new dir %s: %w", semaphoreDir, err)
	}

	return &Semaphore{
		SemaphoreDir: semaphoreDir,
		SemaphoreMap: semaphoreMap,
	}, nil
}

// Return SemaphoreMap to be used with New().
func NewMapping(filepaths []SemaphoreName, semaphoreFileDescs []*SemaphoreFileDesc) (SemaphoreMap, error) {
	if len(filepaths) != len(semaphoreFileDescs) {
		return nil, fmt.Errorf("unequal lengths for filepaths and semaphoreFileDescs")
	}

	mapping := SemaphoreMap{}
	for idx, filepath := range filepaths {
		mapping[filepath] = semaphoreFileDescs[idx]
	}

	return mapping, nil
}

// Check whether semaphore exists.
func (s *Semaphore) Exists(name SemaphoreName) (bool, error) {
	semaphoreDesc, err := s.getSemaphoreDesc(name)
	if err != nil {
		return false, fmt.Errorf("fail to get semaphore description %s: %w", name, err)
	}

	bytes, err := os.ReadFile(semaphoreDesc.Filepath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("fail to read semaphore file %s: %w", name, err)
	}

	if string(bytes) != semaphoreDesc.Content {
		return false, fmt.Errorf("content mismatch for semaphore file %s, want %s, have %s",
			semaphoreDesc.Filepath, semaphoreDesc.Content, string(bytes))
	}

	return true, nil
}

// Check whether semaphore exists, including undefined semaphore not in SemaphoreMap.
func (s *Semaphore) ExistsNew(name SemaphoreName, filename string, content string) (bool, error) {
	s.SemaphoreMap[name] = &SemaphoreFileDesc{
		Filepath: filepath.Join(s.SemaphoreDir, filename),
		Content:  content,
	}

	semaphoreDesc, err := s.getSemaphoreDesc(name)
	if err != nil {
		return false, fmt.Errorf("fail to get semaphore description %s: %w", name, err)
	}

	bytes, err := os.ReadFile(semaphoreDesc.Filepath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("fail to read semaphore file %s: %w", name, err)
	}

	if string(bytes) != semaphoreDesc.Content {
		return false, fmt.Errorf("content mismatch for semaphore file %s, want %s, have %s",
			semaphoreDesc.Filepath, semaphoreDesc.Content, string(bytes))
	}

	return true, nil
}

// Write semaphore with O_CREATE | O_EXCL flags, which guarantees that only one
// semaphore file will be successfully written in a race condition.
func (s *Semaphore) Write(name SemaphoreName) error {
	semaphoreDesc, err := s.getSemaphoreDesc(name)
	if err != nil {
		return fmt.Errorf("fail to get semaphore description %s: %w", name, err)
	}

	f, err := os.OpenFile(semaphoreDesc.Filepath, os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return fmt.Errorf("fail to write semaphore %s: %w", name, err)
	}
	defer f.Close()

	_, err = f.WriteString(semaphoreDesc.Content)
	if err != nil {
		return fmt.Errorf("fail to write semaphore %s: %w", name, err)
	}

	return nil
}

// Write new semaphore that has not been defined. O_CREATE | O_EXCL flags
// guarantee that only one semaphore file will be successfully written in a race
// condition.
func (s *Semaphore) WriteNew(name SemaphoreName, filename string, content string) error {
	f, err := os.OpenFile(filepath.Join(s.SemaphoreDir, filename), os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return fmt.Errorf("fail to write new semaphore %s: %w", name, err)
	}
	defer f.Close()

	_, err = f.WriteString(content)
	if err != nil {
		return fmt.Errorf("fail to write new semaphores %s: %w", name, err)
	}

	s.SemaphoreMap[name] = &SemaphoreFileDesc{
		Filepath: filepath.Join(s.SemaphoreDir, filename),
		Content:  content,
	}

	return nil
}

func (s *Semaphore) Release(name SemaphoreName) error {
	semaphoreDesc, err := s.getSemaphoreDesc(name)
	if err != nil {
		return fmt.Errorf("fail to get semaphore description %s: %w", name, err)
	}

	bytes, err := os.ReadFile(semaphoreDesc.Filepath)
	if err != nil {
		return fmt.Errorf("fail to read semaphore file %s: %w", name, err)
	}

	if string(bytes) != semaphoreDesc.Content {
		return fmt.Errorf("content mismatch for semaphore file %s, want %s, have %s",
			semaphoreDesc.Filepath, semaphoreDesc.Content, string(bytes))
	}

	err = os.Remove(semaphoreDesc.Filepath)
	if err != nil {
		return fmt.Errorf("fail to remove semaphore %s: %w", name, err)
	}

	return nil
}

// Remove all semaphore files including undefined semaphores in semaphore
// directory.
func (s *Semaphore) ClearSemaphoreDir() error {
	err := os.RemoveAll(s.SemaphoreDir)
	if err != nil {
		return fmt.Errorf("fail to clear semaphore directory %s: %w", s.SemaphoreDir, err)
	}
	err = os.MkdirAll(s.SemaphoreDir, 0700)
	if err != nil {
		return fmt.Errorf("fail to recreate semaphore directory %s: %w", s.SemaphoreDir, err)
	}
	return nil
}

func (s *Semaphore) getSemaphoreDesc(name SemaphoreName) (*SemaphoreFileDesc, error) {
	semaphoreDesc, ok := s.SemaphoreMap[name]
	if !ok {
		return nil, fmt.Errorf("undefined semaphore name")
	}
	return semaphoreDesc, nil
}
