package metahelper

import (
	"fmt"
	"log/slog"
	"os"
	"see_updater/internal/pkg/filesystem"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Ascending order, last elem is the latest version of metadata file path.
// Note: this function will panic if there is no version prefix
// i.e. `1.` in `1.role.json`.
func GetRoleMetadataFilepathsFromDir(path string, roleName string) ([]string, error) {
	localFilepaths, fullFilepaths, err := filesystem.GetAllFilepathsInDir(path)
	if err != nil {
		return nil, err
	} else if len(fullFilepaths) == 0 {
		return nil, fmt.Errorf("no file is found in directory")
	}

	targetFilepaths := []string{}
	for i, fullFilepath := range fullFilepaths {
		if strings.Contains(localFilepaths[i], roleName) {
			targetFilepaths = append(targetFilepaths, fullFilepath)
		}
	}
	sort.Slice(targetFilepaths, func(i, j int) bool {
		iList := strings.Split(targetFilepaths[i], string(os.PathSeparator))
		jList := strings.Split(targetFilepaths[j], string(os.PathSeparator))

		iLastPath := iList[len(iList)-1]
		jLastPath := jList[len(jList)-1]

		iVer, err := strconv.Atoi(strings.Split(iLastPath, ".")[0])
		if err != nil {
			panic(fmt.Errorf("fail to parse version prefix number: %w", err))
		}
		jVer, err := strconv.Atoi(strings.Split(jLastPath, ".")[0])
		if err != nil {
			panic(fmt.Errorf("fail to parse version prefix number: %w", err))
		}
		return iVer < jVer
	})
	return targetFilepaths, nil
}

func GenerateNewTargetsFromDir(dirPath string, expireIn time.Time) (*metadata.Metadata[metadata.TargetsType], error) {
	targetLocalFilepaths, targetFullFilepaths, err := filesystem.GetAllFilepathsInDir(dirPath)
	if err != nil {
		return nil, err
	}
	targets := metadata.Targets(expireIn)
	for i, targetFullFilepath := range targetFullFilepaths {
		slog.Debug("generating target file info for file", slog.String("filepath", targetLocalFilepaths[i]))
		targetFileInfo, err := metadata.TargetFile().FromFile(targetFullFilepath)
		if err != nil {
			return nil, (fmt.Errorf("fail to generate target file info for file: %s\n\terror: %w", targetFullFilepath, err))
		}
		targetFileInfo.Path = targetLocalFilepaths[i]
		targets.Signed.Targets[targetLocalFilepaths[i]] = targetFileInfo
	}
	return targets, nil
}

func CompareNewOldTargets(newTargets *metadata.Metadata[metadata.TargetsType],
	oldTargets *metadata.Metadata[metadata.TargetsType],
	sortByPath bool) []struct {
	New metadata.TargetFiles
	Old metadata.TargetFiles
} {
	newChanges := []struct {
		New metadata.TargetFiles
		Old metadata.TargetFiles
	}{}

	newTargetMap := newTargets.Signed.Targets
	oldTargetMap := oldTargets.Signed.Targets

	for _, newTargetInfo := range newTargetMap {
		// Dereference to avoid overwriting pointer memory
		newTargetInfoTmp := *newTargetInfo
		oldTargetInfoTmp := *metadata.TargetFile()
		if oldTargetMap[newTargetInfo.Path] != nil {
			oldTargetInfoTmp = *oldTargetMap[newTargetInfo.Path]
		}

		slog.Debug("Comparing hashes", slog.String("filepath", newTargetInfo.Path),
			slog.Any("new_hash", newTargetInfoTmp.Hashes),
			slog.Any("old_hash", oldTargetInfoTmp.Hashes))
		// fmt.Printf("Comparing %s\n", newTargetInfoTmp.Path)
		// fmt.Printf("\tnew hash: %s\n", newTargetInfoTmp.Hashes)
		// fmt.Printf("\told hash: %s\n", oldTargetInfoTmp.Hashes)

		// Compare new and old target file info
		if oldTargetInfoTmp.Hashes.Equal(newTargetInfoTmp.Hashes) &&
			oldTargetInfoTmp.Length == newTargetInfoTmp.Length &&
			oldTargetInfoTmp.Path == newTargetInfoTmp.Path {
			//fmt.Println("same target file info :D")
			continue
		}

		newChanges = append(newChanges, struct {
			New metadata.TargetFiles
			Old metadata.TargetFiles
		}{
			New: newTargetInfoTmp,
			Old: oldTargetInfoTmp,
		})
		slog.Debug("new changes found", slog.String("filepath", newTargetInfoTmp.Path),
			slog.Int("total_changes", len(newChanges)))
	}

	if sortByPath {
		sort.Slice(newChanges, func(i, j int) bool {
			return newChanges[i].New.Path < newChanges[j].New.Path
		})
	}

	return newChanges
}

// Convert forward slash to backward slash of the Path string
func BackifyForwardSlash(targetInfo *metadata.TargetFiles) *metadata.TargetFiles {
	targetInfo.Path = strings.Replace(targetInfo.Path, "\\", "/", -1)
	return targetInfo
}
