package filesystem

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func IsDirWritable(path string) (bool, error) {
	tmpFile := "tmpfile_check_writable"

	file, err := os.CreateTemp(path, tmpFile)
	if err != nil {
		return false, err
	}

	defer os.Remove(file.Name())
	defer file.Close()

	return true, nil
}

func ReadBytesFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func WriteStringToFile(path string, str string) error {
	data := []byte(str)
	err := os.WriteFile(path, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

func WriteBytesToFile(path string, bytes []byte) error {
	err := os.WriteFile(path, bytes, 0644)
	if err != nil {
		return err
	}

	return nil
}

// Returns all localFilepaths, fullFilepaths in the directory
func GetAllFilepathsInDir(path string) ([]string, []string, error) {
	var localFilepaths, fullFilepaths []string

	_, root := filepath.Split(filepath.Clean(path)) // Local root (Last dirname in dirpath)
	err := filepath.WalkDir(path, func(path string, di fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("fail to access path %q: %w\n", path, err)
		}
		// if info.IsDir() && info.Name() == subDirToSkip {
		// 	fmt.Printf("skipping a dir without errors: %+v \n", info.Name())
		// 	return filepath.SkipDir
		// }
		if !di.IsDir() {
			// Split full filepath into parts by separator
			filepathParts := strings.Split(path, string(os.PathSeparator))
			for i, part := range filepathParts {
				// Join filepath parts that are after root
				if part == root {
					localFilepath := strings.Join(filepathParts[i:], string(os.PathSeparator))

					// Append current filepath to list
					localFilepaths = append(localFilepaths, localFilepath)
					fullFilepaths = append(fullFilepaths, path)

					slog.Debug("visited file", slog.String("filepath", path), slog.String("added_as", localFilepath))
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error walking the path %q: %w", path, err)
	}
	return localFilepaths, fullFilepaths, nil
}

// Panic if fails
func Remove(path string) {
	err := os.RemoveAll(path)
	if err != nil {
		panic(err)
	}
}

func MakeNewDir(path string) error {
	err := os.Mkdir(path, 0700) // user can write
	if err != nil {
		return err
	}
	return nil
}

func MakeNewDirAll(path string) error {
	err := os.MkdirAll(path, 0700) // user can write
	if err != nil {
		return err
	}
	return nil
}

// Returns `true` if file is available,
// otherwise return `false` with error.
func IsFileAvailable(dirPath string, filename string) (bool, error) {
	_, err := os.Stat(filepath.Join(dirPath, filename))
	if err != nil {
		return false, err
	}
	return true, nil
}

// Returns `true` if file is available,
// otherwise return `false` with error.
func IsFileAvailableP(dirPath string) (bool, error) {
	_, err := os.Stat(dirPath)
	if err != nil {
		return false, err
	}
	return true, nil
}

func SprintDirTree(dirPath string, newRootName string) (string, error) {
	tree := fmt.Sprintf("ROOT: ")
	if newRootName == "" {
		tree += fmt.Sprintf("%s\n", dirPath)
	} else {
		tree += fmt.Sprintf("%s\n", newRootName)
	}

	res, err := sprintDir(dirPath, 0, "")
	if err != nil {
		return "", err
	}
	tree += res
	return tree, nil
}

// Helper for SprintDirTree
func sprintDir(dirPath string, depth int, parentPath string) (string, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return "", fmt.Errorf("fail to read dir %s: %w", dirPath, err)
	}
	// Sort by file type, file preceds dir
	slices.SortFunc(entries, func(a fs.DirEntry, b fs.DirEntry) int {
		if a.IsDir() && b.IsDir() {
			return 0
		} else if a.IsDir() && !b.IsDir() {
			return 1
		} else {
			return -1
		}
	})
	res := ""
	for idx, entry := range entries {
		for d := 0; d < depth; d++ {
			res += "  "
		}
		if idx == len(entries)-1 {
			res += "`--"
		} else {
			res += "|--"
		}

		res += parentPath
		if entry.IsDir() {
			res += fmt.Sprintf("%s\\\n", entry.Name())
			childTree, err := sprintDir(filepath.Join(dirPath, entry.Name()), depth+1, parentPath+entry.Name()+"\\")
			if err != nil {
				return res, err
			}
			res += childTree
		} else {
			res += fmt.Sprintf("%s\n", entry.Name())
		}
	}
	return res, nil
}
