package repository

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"see_updater/internal/pkg/datetime"
	"see_updater/internal/pkg/logging"
	"see_updater/internal/pkg/metahelper"

	// "github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

const placeholderExpireIn = 1000

type verResult struct {
	filepath       string
	threshold      uint8
	keyIDs         []string
	expirationDate time.Time
	valid          bool
	errorMessages  []error
}

type verResults map[string]verResult

func verifyMetadata(config configVerify) error {
	// Append context to logger
	ctx := logging.AppendCtx(context.Background(), slog.Group("config",
		slog.String("metadata_dir", config.metadataDir),
		slog.String("respository_dir", config.repositoryDir),
	))

	roles := repository.New()
	verResults := verResults{}

	// Load old metadata files for all roles from files
	root := metadata.Root(datetime.ExpireIn(placeholderExpireIn))
	roles.SetRoot(root)
	rootFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Root)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata filepaths", slog.Any("error", err), slog.String("role", Root))
		return fmt.Errorf("fail to load metadata filepaths: %w", err)
	}
	_, err = roles.Root().FromFile(rootFilepaths[len(rootFilepaths)-1])
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata from file", slog.Any("error", err), slog.String("role", Root))
		return fmt.Errorf("fail to load metadata from file\n\terror: %w", err)
	}

	// Load targets metadata file
	targets := metadata.Targets(datetime.ExpireIn(placeholderExpireIn))
	roles.SetTargets(Targets, targets)
	targetMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Targets)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load target metadata", slog.Any("error", err), slog.String("role", Targets))
		return fmt.Errorf("fail to load metadata filepaths: %w", err)
	}
	targets, err = roles.Targets(Targets).FromFile(targetMetadataFilepaths[len(targetMetadataFilepaths)-1])
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata from file", slog.Any("error", err), slog.String("role", Targets))
		return fmt.Errorf("fail to load metadata from file\n\terror: %w", err)
	}

	// Load snapshot metadata file
	snapshot := metadata.Snapshot(datetime.ExpireIn(placeholderExpireIn))
	roles.SetSnapshot(snapshot)
	snapshotMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Snapshot)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load target metadata", slog.Any("error", err), slog.String("role", Snapshot))
		return fmt.Errorf("fail to load metadata filepaths: %w", err)
	}
	snapshot, err = roles.Snapshot().FromFile(snapshotMetadataFilepaths[len(snapshotMetadataFilepaths)-1])
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata from file", slog.Any("error", err), slog.String("role", Snapshot))
		return fmt.Errorf("fail to load metadata from file\n\terror: %w", err)
	}

	// Load timestamp metadata file
	timestamp := metadata.Timestamp(datetime.ExpireIn(placeholderExpireIn))
	roles.SetTimestamp(timestamp)
	timestampMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Timestamp)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load target metadata", slog.Any("error", err), slog.String("role", Timestamp))
		return fmt.Errorf("fail to load metadata filepaths: %w", err)
	}
	timestamp, err = roles.Timestamp().FromFile(timestampMetadataFilepaths[len(timestampMetadataFilepaths)-1])
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata from file", slog.Any("error", err), slog.String("role", Timestamp))
		return fmt.Errorf("fail to load metadata from file\n\terror: %w", err)
	}

	// Load attributes
	for _, name := range getRoles() {
		entry := verResults[name]
		switch name {
		case Targets:
			entry.expirationDate = roles.Targets(Targets).Signed.Expires
			entry.filepath = targetMetadataFilepaths[len(targetMetadataFilepaths)-1]
		case Snapshot:
			entry.expirationDate = roles.Snapshot().Signed.Expires
			entry.filepath = snapshotMetadataFilepaths[len(snapshotMetadataFilepaths)-1]
		case Timestamp:
			entry.expirationDate = roles.Timestamp().Signed.Expires
			entry.filepath = timestampMetadataFilepaths[len(timestampMetadataFilepaths)-1]
		case Root:
			entry.expirationDate = roles.Root().Signed.Expires
			entry.filepath = rootFilepaths[len(rootFilepaths)-1]
		}

		entry.threshold = uint8(roles.Root().Signed.Roles[name].Threshold)
		entry.keyIDs = roles.Root().Signed.Roles[name].KeyIDs
		entry.valid = true
		verResults[name] = entry
	}

	// Verify
	for _, name := range []string{Root, Timestamp, Snapshot, Targets} { // The ordering is IMPORTANT root > timestamp > snapshot > targets
		entry := verResults[name]
		switch name {
		case Targets:
			err = roles.Root().VerifyDelegate(Targets, targets)
			if err != nil {
				slog.Warn("fail to verify targets metadata signature", "error", err)
				entry.errorMessages = append(entry.errorMessages, err)
				entry.valid = false
			}
			if isExp := roles.Targets(Targets).Signed.IsExpired(time.Now()); isExp {
				slog.Warn("targets metadata expired", slog.Any("valid_until", verResults[name].expirationDate))
				entry.errorMessages = append(entry.errorMessages, fmt.Errorf("TARGETS metadata expired"))
				entry.valid = false
			}
		case Snapshot:
			err = roles.Root().VerifyDelegate(Snapshot, snapshot)
			if err != nil {
				slog.Warn("fail to verify snapshot metadata signature", "error", err)
				entry.errorMessages = append(entry.errorMessages, err)
				entry.valid = false
			}
			if isExp := roles.Snapshot().Signed.IsExpired(time.Now()); isExp {
				slog.Warn("snapshot metadata expired", slog.Any("valid_until", verResults[name].expirationDate))
				entry.errorMessages = append(entry.errorMessages, fmt.Errorf("SNAPSHOT metadata expired"))
				entry.valid = false
			}
		case Timestamp:
			err = roles.Root().VerifyDelegate(Timestamp, timestamp)
			if err != nil {
				slog.Warn("fail to verify timestamp metadata signature", "error", err)
				entry.errorMessages = append(entry.errorMessages, err)
				entry.valid = false
			}
			if isExp := roles.Timestamp().Signed.IsExpired(time.Now()); isExp {
				slog.Warn("timestamp metadata expired", slog.Any("valid_until", verResults[name].expirationDate))
				entry.errorMessages = append(entry.errorMessages, fmt.Errorf("TIMESTAMP metadata expired"))
				entry.valid = false
			}
		case Root:
			err = roles.Root().VerifyDelegate(Root, root)
			if err != nil {
				slog.Warn("fail to verify root metadata signature", "error", err)
				entry.errorMessages = append(entry.errorMessages, err)
				entry.valid = false
			}
			if isExp := roles.Root().Signed.IsExpired(time.Now()); isExp {
				slog.Warn("root metadata expired", slog.Any("valid_until", verResults[name].expirationDate))
				entry.errorMessages = append(entry.errorMessages, fmt.Errorf("ROOT metadata expired"))
				entry.valid = false
			}
		}
		verResults[name] = entry
	}

	newTargets, err := metahelper.GenerateNewTargetsFromDir(config.repositoryDir, datetime.ExpireIn(placeholderExpireIn))
	if err != nil {
		return err
	}
	newChanges := metahelper.CompareNewOldTargets(newTargets, targets, true)
	fmt.Printf("A total of %d new changes detected:\n", len(newChanges))
	w := tabwriter.NewWriter(os.Stdout, 1, 2, 1, ' ', 0)
	fmt.Fprintln(w, "\tNo.\tFilepath\tLength (old -> new)")
	for i, change := range newChanges {
		fmt.Fprintf(w, "\t%d.\t%s\t%d\t->\t%d\n", i+1, change.New.Path, change.Old.Length, change.New.Length)
	}
	w.Flush()

	var hasError = false
	w = tabwriter.NewWriter(os.Stdout, 1, 2, 1, ' ', 0)
	fmt.Fprintf(w, "\tNo.\tRole\tFilepath\tThreshold\tExpiration\tValid\tError(s)")
	for i, name := range getRoles() {
		verRes := verResults[name]
		fmt.Fprintf(w, "\n\t%d.\t%s\t%s\t%d\t%s\t%v\t",
			i+1, name, verRes.filepath, verRes.threshold, verRes.expirationDate, verRes.valid)
		for j, errMsg := range verRes.errorMessages {
			if j != 0 {
				fmt.Fprintf(w, "\n\t\t\t\t\t\t\t")
			}
			fmt.Fprintf(w, "%d. %v", j+1, errMsg)
		}

		if len(verRes.errorMessages) > 0 {
			hasError = true
		}
	}
	w.Flush()
	fmt.Printf("\n")
	if hasError {
		return fmt.Errorf("errors are printed above")
	}

	// Begin trusted metadata verification workflow
	// ROOT > TIMESTAMP > SNAPSHOT > TARGETS
	slog.Info("Beginning trusted metadata verification workflow: ROOT > TIMESTAMP > SNAPSHOT > TARGETS")
	rootBytes, err := roles.Root().ToBytes(true)
	if err != nil {
		slog.ErrorContext(ctx, "fail to convert root into bytes")
	}
	trustedMetadata, err := trustedmetadata.New(rootBytes)
	if err != nil {
		slog.ErrorContext(ctx, "fail to init root trustedMedata for verification")
		return err
	}
	slog.Info("Root trusted metadata verification PASSED, remaining: timestamp & snapshot & targets")

	// TIMESTAMP
	if timestampBytes, err := roles.Timestamp().ToBytes(true); err != nil {
		slog.ErrorContext(ctx, "fail to convert timestamp into bytes for verification")
	} else {
		if _, err = trustedMetadata.UpdateTimestamp(timestampBytes); err != nil {
			slog.ErrorContext(ctx, "fail to verify timestamp", slog.Any("error", err))
			return err
		}
	}
	slog.Info("Root & timestamp trusted metadata verification PASSED, remaining: snapshot & targets")

	// SNAPSHOT
	if snapshotBytes, err := roles.Snapshot().ToBytes(true); err != nil {
		slog.ErrorContext(ctx, "fail to convert snapshot into bytes for verification")
	} else {
		if _, err = trustedMetadata.UpdateSnapshot(snapshotBytes, false); err != nil {
			slog.ErrorContext(ctx, "fail to verify snpashot", slog.Any("error", err))
			return err
		}
	}
	slog.Info("Root & timestamp & snapshot trusted metadata verification PASSED, remaining: targets")

	// TARGETS
	if targetsBytes, err := roles.Targets(Targets).ToBytes(true); err != nil {
		slog.ErrorContext(ctx, "fail to convert targets into bytes for verification")

	} else {
		if _, err = trustedMetadata.UpdateTargets(targetsBytes); err != nil {
			slog.ErrorContext(ctx, "fail to verify targets", slog.Any("error", err))
			return err
		}
	}
	slog.Info("All trusted metadata verification PASSED")

	// Begin root metadata file key continuity test
	previousRoot := metadata.Root(datetime.ExpireIn(placeholderExpireIn))
	_, err = previousRoot.FromFile(rootFilepaths[0])
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata from file", slog.Any("error", err), slog.String("role", Root))
		return fmt.Errorf("fail to load metadata from file\n\terror: %w", err)
	}
	for i, filepath := range rootFilepaths[1:] {
		root := metadata.Root(datetime.ExpireIn(placeholderExpireIn))
		_, err := root.FromFile(filepath)
		if err != nil {
			slog.ErrorContext(ctx, "fail to load metadata from file", slog.Any("error", err), slog.String("role", Root))
			return fmt.Errorf("fail to load metadata from file\n\terror: %w", err)
		}
		err = previousRoot.VerifyDelegate(Root, root)
		if err != nil {
			slog.ErrorContext(ctx, "fail to verify root key continuity", slog.Any("error", err), slog.Int("metadata version", i+2)) // i+2 as list 0th = version 1
			return err
		}
		previousRoot = root
	}

	return nil
}
