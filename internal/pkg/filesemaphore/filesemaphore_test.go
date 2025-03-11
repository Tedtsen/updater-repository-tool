package filesemaphore_test

import (
	"fmt"
	"os"
	"path/filepath"
	"see_updater/internal/pkg/filesemaphore"
	"sync"
	"testing"
)

func TestSemaphore(t *testing.T) {
	semaphoreDir := "../../../test/test-semaphore-dir"

	smap, err := filesemaphore.NewMapping(
		[]filesemaphore.SemaphoreName{
			"first", "second", "third",
		},
		[]*filesemaphore.SemaphoreFileDesc{
			{
				Filepath: filepath.Join(semaphoreDir, "first_file"),
				Content:  "first_semaphore",
			},
			{
				Filepath: filepath.Join(semaphoreDir, "second_file"),
				Content:  "second_semaphore",
			},
			{
				Filepath: filepath.Join(semaphoreDir, "third_file"),
				Content:  "third_semaphore",
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	s, err := filesemaphore.New(semaphoreDir, smap)
	if err != nil {
		t.Fatal(err)
	}

	// Check does not exist
	for _, name := range []filesemaphore.SemaphoreName{"first", "second", "third"} {
		semaphoreExists, err := s.Exists(name)
		if semaphoreExists == true {
			os.RemoveAll(semaphoreDir)
			t.Fatal(err)
		}
	}

	// Write
	for _, name := range []filesemaphore.SemaphoreName{"first", "second", "third"} {
		err = s.Write(name)
		if err != nil {
			os.RemoveAll(semaphoreDir)
			t.Fatal(err)
		}
	}

	// Check exists
	for _, name := range []filesemaphore.SemaphoreName{"first", "second", "third"} {
		semaphoreExists, err := s.Exists(name)
		if err != nil || semaphoreExists != true {
			os.RemoveAll(semaphoreDir)
			t.Fatal(err)
		}
	}

	// Remove
	err = s.Release("first")
	if err != nil {
		t.Fatal(err)
	}
	semaphoreExists, err := s.Exists("first")
	if semaphoreExists {
		t.Fatal(err)
	}
	for _, name := range []filesemaphore.SemaphoreName{"second", "third"} {
		semaphoreExists, err := s.Exists(name)
		if err != nil || semaphoreExists != true {
			os.RemoveAll(semaphoreDir)
			t.Fatal(err)
		}
	}

	os.RemoveAll(semaphoreDir)
}

func TestSemaphore_ConcurrentWriteSameFile(t *testing.T) {
	semaphoreDir := "../../../test/test-semaphore-concurrent-dir"

	names := []filesemaphore.SemaphoreName{"sem"}
	fileDescs := []*filesemaphore.SemaphoreFileDesc{
		{
			Filepath: filepath.Join(semaphoreDir, "sem"),
			Content:  "sem",
		},
	}

	smap, err := filesemaphore.NewMapping(names, fileDescs)
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	s, err := filesemaphore.New(semaphoreDir, smap)
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	blocking := make(chan struct{})
	var wg sync.WaitGroup
	var errCount = 0
	for idx := 0; idx < 100; idx++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-blocking
			err := s.Write("sem")
			if err != nil {
				fmt.Println(err)
				errCount++
			}
		}()
	}
	close(blocking)
	wg.Wait()
	if errCount != 99 {
		os.RemoveAll(semaphoreDir)
		t.Fatalf("concurrent write test fails errCount=%d", errCount)
	}
	os.RemoveAll(semaphoreDir)
}

func TestSemaphore_SameFileDifferentContent(t *testing.T) {
	semaphoreDir := "../../../test/test-semaphore-sfdc-dir"

	names := []filesemaphore.SemaphoreName{"sem1", "sem2"}
	fileDescs := []*filesemaphore.SemaphoreFileDesc{
		{
			Filepath: filepath.Join(semaphoreDir, "sem"),
			Content:  "sem1",
		},
		{
			Filepath: filepath.Join(semaphoreDir, "sem"),
			Content:  "sem2",
		},
	}

	smap, err := filesemaphore.NewMapping(names, fileDescs)
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	s, err := filesemaphore.New(semaphoreDir, smap)
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	err = s.Write("sem1")
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	err = s.Write("sem2")
	if err == nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	sem1Exists, err := s.Exists("sem1")
	if err != nil || !sem1Exists {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	sem2Exists, err := s.Exists("sem2")
	if err == nil || sem2Exists {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	os.RemoveAll(semaphoreDir)
}

func TestSemaphore_UndefinedSemaphores(t *testing.T) {
	semaphoreDir := "../../../test/test-semaphore-us-dir"

	names := []filesemaphore.SemaphoreName{"sem1"}
	fileDescs := []*filesemaphore.SemaphoreFileDesc{
		{
			Filepath: filepath.Join(semaphoreDir, "sem"),
			Content:  "sem1",
		},
	}

	smap, err := filesemaphore.NewMapping(names, fileDescs)
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	s, err := filesemaphore.New(semaphoreDir, smap)
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Should not exist
	sem2Exists, err := s.Exists("sem2")
	if err == nil || sem2Exists {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Write new undefined semaphore
	err = s.WriteNew("sem2", "sem2", "sem2content")
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Should exist
	sem2Exists, err = s.Exists("sem2")
	if err != nil || !sem2Exists {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Should exist
	sem2Exists, err = s.ExistsNew("sem2", "sem2", "sem2content")
	if err != nil || !sem2Exists {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Create new Semaphore
	sNew, err := filesemaphore.New(semaphoreDir, filesemaphore.SemaphoreMap{})
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Use old Semaphore to write
	err = s.Write("sem1")
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Should not exist
	sem1Exists, err := sNew.Exists("sem1")
	if err == nil || sem1Exists {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Should exists
	sem1Exists, err = sNew.ExistsNew("sem1", "sem", "sem1")
	if err != nil || !sem1Exists {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Should  exist
	sem1Exists, err = sNew.Exists("sem1")
	if err != nil || !sem1Exists {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	os.RemoveAll(semaphoreDir)
}

func TestSemaphore_RemoveAll(t *testing.T) {
	semaphoreDir := "../../../test/test-semaphore-rmall-dir"

	names := []filesemaphore.SemaphoreName{"sem1"}
	fileDescs := []*filesemaphore.SemaphoreFileDesc{
		{
			Filepath: filepath.Join(semaphoreDir, "sem"),
			Content:  "sem1",
		},
	}

	smap, err := filesemaphore.NewMapping(names, fileDescs)
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	s, err := filesemaphore.New(semaphoreDir, smap)
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Should not exist
	sem2Exists, err := s.Exists("sem2")
	if err == nil || sem2Exists {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Write new undefined semaphore
	err = s.WriteNew("sem2", "sem2", "sem2content")
	if err != nil {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Should exist
	sem2Exists, err = s.Exists("sem2")
	if err != nil || !sem2Exists {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}

	// Should exist
	sem2Exists, err = s.ExistsNew("sem2", "sem2", "sem2content")
	if err != nil || !sem2Exists {
		os.RemoveAll(semaphoreDir)
		t.Fatal(err)
	}
}

func TestSemaphore_ClearSemaphoreDir(t *testing.T) {
	semaphoreDir := "../../../test/test-clear-semaphore-dir"

	smap, err := filesemaphore.NewMapping(
		[]filesemaphore.SemaphoreName{
			"first", "second", "third",
		},
		[]*filesemaphore.SemaphoreFileDesc{
			{
				Filepath: filepath.Join(semaphoreDir, "first_file"),
				Content:  "first_semaphore",
			},
			{
				Filepath: filepath.Join(semaphoreDir, "second_file"),
				Content:  "second_semaphore",
			},
			{
				Filepath: filepath.Join(semaphoreDir, "third_file"),
				Content:  "third_semaphore",
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	s, err := filesemaphore.New(semaphoreDir, smap)
	if err != nil {
		t.Fatal(err)
	}

	// Check does not exist
	for _, name := range []filesemaphore.SemaphoreName{"first", "second", "third"} {
		semaphoreExists, err := s.Exists(name)
		if semaphoreExists == true {
			os.RemoveAll(semaphoreDir)
			t.Fatal(err)
		}
	}

	// Write
	for _, name := range []filesemaphore.SemaphoreName{"first", "second", "third"} {
		err = s.Write(name)
		if err != nil {
			os.RemoveAll(semaphoreDir)
			t.Fatal(err)
		}
	}

	// Write new
	err = s.WriteNew("fourth", "fourth", "fourth")
	if err != nil {
		t.Fatal(err)
	}

	// Check exists
	for _, name := range []filesemaphore.SemaphoreName{"first", "second", "third", "fourth"} {
		semaphoreExists, err := s.Exists(name)
		if err != nil || semaphoreExists != true {
			os.RemoveAll(semaphoreDir)
			t.Fatal(err)
		}
	}

	// Remove
	err = s.Release("first")
	if err != nil {
		t.Fatal(err)
	}
	semaphoreExists, err := s.Exists("first")
	if semaphoreExists {
		t.Fatal(err)
	}
	for _, name := range []filesemaphore.SemaphoreName{"second", "third", "fourth"} {
		semaphoreExists, err := s.Exists(name)
		if err != nil || semaphoreExists != true {
			os.RemoveAll(semaphoreDir)
			t.Fatal(err)
		}
	}

	err = s.ClearSemaphoreDir()
	if err != nil {
		t.Fatal(err)
	}
	// Should not exist
	for _, name := range []filesemaphore.SemaphoreName{"second", "third", "fourth"} {
		semaphoreExists, err := s.Exists(name)
		if semaphoreExists == true {
			os.RemoveAll(semaphoreDir)
			t.Fatal(err)
		}
	}

	os.RemoveAll(semaphoreDir)
}
