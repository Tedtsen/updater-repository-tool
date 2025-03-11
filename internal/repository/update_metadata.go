package repository

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"text/tabwriter"

	"see_updater/internal/pkg/cli"
	"see_updater/internal/pkg/cryptography"
	"see_updater/internal/pkg/datetime"
	"see_updater/internal/pkg/filesystem"
	"see_updater/internal/pkg/logging"
	"see_updater/internal/pkg/metahelper"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/repository"
)

func updateMetadata(config configUpdate) error {
	// Append context to logger
	ctx := logging.AppendCtx(context.Background(), slog.Group("config",
		slog.String("repository_dir", config.repositoryDir),
		slog.String("metadata_dir", config.metadataDir),
		slog.String("targets_privkey_filepath", config.targetsPrivkeyFilepath),
		slog.String("snapshot_privkey_filepath", config.snapshotPrivkeyFilepath),
		slog.String("timestamp_privkey_filepath", config.timestampPrivkeyFilepath),
		slog.Int("expire_in", int(config.expireIn)),
		slog.Bool("ask_confirmation", config.askConfirmation),
	))

	roles := repository.New()

	// Load old metadata files for all roles from files
	root := metadata.Root(datetime.ExpireIn(int(config.expireIn)))
	roles.SetRoot(root)
	rootFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Root)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata filepaths", slog.Any("error", err), slog.String("role", Root))
		return fmt.Errorf("fail to load metadata filepaths: %w", err)
	}
	_, err = roles.Root().FromFile(rootFilepaths[len(rootFilepaths)-1])
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata from file", slog.Any("error", err), slog.String("role", Root))
		return fmt.Errorf("fail to load metadata from file: %w", err)
	}

	// Load old targets metadata file
	targets := metadata.Targets(datetime.ExpireIn(int(config.expireIn)))
	roles.SetTargets(Targets, targets)
	targetMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Targets)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata filepaths", slog.Any("error", err), slog.String("role", Targets))
		return fmt.Errorf("fail to load metadata filepaths: %w", err)
	}
	oldTargets, err := roles.Targets(Targets).FromFile(targetMetadataFilepaths[len(targetMetadataFilepaths)-1])
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata from file", slog.Any("error", err), slog.String("role", Targets))
		return fmt.Errorf("fail to load metadata from file: %w", err)
	}

	// Load old snapshot metadata file
	snapshot := metadata.Snapshot(datetime.ExpireIn(int(config.expireIn)))
	roles.SetSnapshot(snapshot)
	snapshotMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Snapshot)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata filepaths", slog.Any("error", err), slog.String("role", Snapshot))
		return fmt.Errorf("fail to load metadata filepaths: %w", err)
	}
	oldSnapshot, err := roles.Snapshot().FromFile(snapshotMetadataFilepaths[len(snapshotMetadataFilepaths)-1])
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata from file", slog.Any("error", err), slog.String("role", Snapshot))
		return fmt.Errorf("fail to load snapshot metadata from file: %w", err)
	}

	// Load old timestamp metadata file
	timestamp := metadata.Timestamp(datetime.ExpireIn(int(config.expireIn)))
	roles.SetTimestamp(timestamp)
	timestampMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Timestamp)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata filepaths", slog.Any("error", err), slog.String("role", Timestamp))
		return fmt.Errorf("fail to load metadata filepaths: %w", err)

	}
	oldTimestamp, err := roles.Timestamp().FromFile(timestampMetadataFilepaths[len(timestampMetadataFilepaths)-1])
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata from file", slog.Any("error", err), slog.String("role", Timestamp))
		return fmt.Errorf("fail to load timestamp metadata from file: %w", err)
	}

	// Verify older version before proceeding to write the newer version
	for _, name := range getRoles() {
		switch name {
		case Targets:
			err = roles.Root().VerifyDelegate(Targets, oldTargets)
			if err != nil {
				slog.ErrorContext(ctx, "fail to verify metadata signature for previous version",
					slog.Any("error", err), slog.String("role", name))
				slog.Info("Update aborted and no changes were made")
				return fmt.Errorf("fail to verify TARGETS metadata signature for PREVIOUS version: %w", err)

			}
		case Snapshot:
			err = roles.Root().VerifyDelegate(Snapshot, oldSnapshot)
			if err != nil {
				slog.ErrorContext(ctx, "fail to verify metadata signature for previous version",
					slog.Any("error", err), slog.String("role", name))
				slog.Info("Update aborted and no changes were made")
				return fmt.Errorf("fail to verify SNAPSHOT metadata signature for PREVIOUS version: %w", err)

			}
		case Timestamp:
			err = roles.Root().VerifyDelegate(Timestamp, oldTimestamp)
			if err != nil {
				slog.ErrorContext(ctx, "fail to verify metadata signature for previous version",
					slog.Any("error", err), slog.String("role", name))
				slog.Info("Update aborted and no changes were made")
				return fmt.Errorf("fail to verify TIMESTAMP metadata signature for PREVIOUS version: %w", err)

			}
		case Root:
			err = roles.Root().VerifyDelegate(Root, root)
			if err != nil {
				slog.ErrorContext(ctx, "fail to verify metadata signature for previous version",
					slog.Any("error", err), slog.String("role", name))
				slog.Info("Update aborted and no changes were made")
				return fmt.Errorf("fail to verify ROOT metadata signature for PREVIOUS version: %w", err)
			}
		}
	}

	// Generate new target metadata files from files in directory
	newTargets, err := metahelper.GenerateNewTargetsFromDir(config.repositoryDir, datetime.ExpireIn(7))
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		return err
	}

	// Compare new and old versions
	newChanges := metahelper.CompareNewOldTargets(newTargets, oldTargets, true)

	// Check if no new changes and abort
	// if (len(newChanges) == 0) {
	// 	fmt.Println("no new changes detected, metadata files update operation aborted")
	// 	return
	// }

	// Show changes and ask user confirmation to continue the update operation
	fmt.Printf("A total of %d new changes detected:\n", len(newChanges))
	w := tabwriter.NewWriter(os.Stdout, 1, 2, 1, ' ', 0)
	fmt.Fprintln(w, "\tNo.\tFilepath\tLength (old -> new)")
	for i, change := range newChanges {
		fmt.Fprintf(w, "\t%d.\t%s\t%d\t->\t%d\n", i+1, change.New.Path, change.Old.Length, change.New.Length)
	}
	w.Flush()
	if config.askConfirmation && !cli.AskConfirmation(3) {
		return fmt.Errorf("fail to confirm operation")
	}

	// Clear old signatures, update roles info, bump version
	roleNames := []string{Targets, Snapshot, Timestamp} // root metadata won't be touched
	for _, name := range roleNames {
		switch name {
		case Targets:
			roles.Targets(Targets).ClearSignatures()
			roles.SetTargets(Targets, newTargets)
			roles.Targets(Targets).Signed.Version = oldTargets.Signed.Version + 1
			roles.Targets(Targets).Signed.Expires = datetime.ExpireIn(int(config.expireIn))
		case Snapshot:
			roles.Snapshot().ClearSignatures()
			roles.Snapshot().Signed.Meta[Targets+".json"] = metadata.MetaFile(roles.Targets(Targets).Signed.Version)
			roles.Snapshot().Signed.Version += 1
			roles.Snapshot().Signed.Expires = datetime.ExpireIn(int(config.expireIn))
		case Timestamp:
			roles.Timestamp().ClearSignatures()
			roles.Timestamp().Signed.Meta[Snapshot+".json"] = metadata.MetaFile(roles.Snapshot().Signed.Version)
			roles.Timestamp().Signed.Version += 1
			roles.Timestamp().Signed.Expires = datetime.ExpireIn(int(config.expireIn))
		}
	}

	// Load keys for signing
	keys := map[string]*rsa.PrivateKey{}
	for _, name := range roleNames {
		path := ""
		switch name {
		case Targets:
			path = config.targetsPrivkeyFilepath
		case Snapshot:
			path = config.snapshotPrivkeyFilepath
		case Timestamp:
			path = config.timestampPrivkeyFilepath
		}
		if len(path) == 0 {
			continue
		}
		bytes, err := filesystem.ReadBytesFromFile(path)
		if err != nil {
			slog.ErrorContext(ctx, err.Error())
			return err
		}
		privkey, err := cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
		if err != nil {
			slog.ErrorContext(ctx, err.Error())
			return err
		}
		keys[name] = privkey
	}

	// Check if keys are valid for roles
	for name, key := range keys {
		keyMetadata, err := metadata.KeyFromPublicKey(key.Public())
		if err != nil {
			return err
		}
		if !slices.Contains(roles.Root().Signed.Roles[name].KeyIDs, keyMetadata.ID()) {
			slog.ErrorContext(ctx, "invalid key for role", slog.String("role", name))
			return fmt.Errorf("invalid key for role : %s", name)
		}
	}

	// Signing
	for _, name := range roleNames {
		key := keys[name]
		if key == nil {
			slog.InfoContext(ctx, fmt.Sprintf("No key provided for role: %s, skipping signing operation\n", name))
			continue // If key not provided, skip
		}
		signer, err := signature.LoadSigner(key, crypto.SHA256)
		if err != nil {
			slog.ErrorContext(ctx, "fail to load signer", slog.Any("error", err), slog.String("role", name))
			return fmt.Errorf("fail to load signer for role: %s\n\terror: %w", name, err)
		}
		switch name {
		case Targets:
			roles.Targets(Targets).ClearSignatures()
			_, err = roles.Targets(Targets).Sign(signer)
			if err != nil {
				slog.ErrorContext(ctx, "fail to load signer", slog.Any("error", err), slog.String("role", name))
				return fmt.Errorf("fail to sign metadata for role: %s\n\terror: %w", name, err)
			}
		case Snapshot:
			roles.Snapshot().ClearSignatures()
			_, err = roles.Snapshot().Sign(signer)
			if err != nil {
				slog.ErrorContext(ctx, "fail to load signer", slog.Any("error", err), slog.String("role", name))
				return fmt.Errorf("fail to sign metadata for role: %s\n\terror: %w", name, err)
			}
		case Timestamp:
			roles.Timestamp().ClearSignatures()
			_, err = roles.Timestamp().Sign(signer)
			if err != nil {
				slog.ErrorContext(ctx, "fail to load signer", slog.Any("error", err), slog.String("role", name))
				return fmt.Errorf("fail to sign metadata for role: %s\n\terror: %w", name, err)
			}
		}
	}

	// Check duplicate (REDUNDANT: don't have to check, update is similar to init where newer version of metadata files will be created without any signature)
	sigCount := map[string]int{}
	for _, sig := range roles.Targets(Targets).Signatures {
		sigCount[sig.KeyID] += 1
		if sigCount[sig.KeyID] > 1 {
			slog.ErrorContext(ctx, "duplicate signature found", slog.String("role", Targets),
				slog.Int("signature_count", sigCount[sig.KeyID]), slog.String("key_id", sig.KeyID))
			return fmt.Errorf("duplicate signature found")
		}
	}

	// Verify newer version and prompt reminder for omitted keys
	var verErr error
	for _, name := range roleNames {
		switch name {
		case Targets:
			verErr = roles.Root().VerifyDelegate(Targets, roles.Targets(Targets))
			if verErr != nil {
				slog.Warn("fail to verify targets metadata signature for new version", slog.Any("error", verErr), slog.String("role", name))
			}
		case Snapshot:
			verErr = roles.Root().VerifyDelegate(Snapshot, roles.Snapshot())
			if verErr != nil {
				slog.Warn("fail to verify snapshot metadata signature for new version", slog.Any("error", verErr), slog.String("role", name))
			}
		case Timestamp:
			verErr = roles.Root().VerifyDelegate(Timestamp, roles.Timestamp())
			if verErr != nil {
				slog.Warn("fail to verify timestamp metadata signature for new version", slog.Any("error", verErr), slog.String("role", name))
			}
		}
		if verErr != nil {
			// Two scenarios:
			// 1. User used the RIGHT key to sign, but total RIGHT signature < threshold
			// 2. User used the WRONG key to sign, total RIGHT signature < threshold
			fmt.Println("Please make sure that the right keys were used, otherwise please perform additional signing to meet the threshold")
			fmt.Println("Program will now proceed to write the signature to the metadata file (irreversible)")
			if config.askConfirmation && !cli.AskConfirmation(3) {
				fmt.Println("Operation aborted, no changes were made")
				return fmt.Errorf("fail to confirm operation")
			}
		}
	}

	// Write even if unsigned, so can load and sign later
	// Write metadata for all changed roles except for root
	// Attempt write
	_, err = filesystem.IsDirWritable(config.metadataDir)
	if err != nil {
		return (err)
	}
	succeededWrites := []string{} // To removed written files in case of error
	for _, name := range roleNames {
		filename := ""
		switch name {
		case Targets:
			filename = fmt.Sprintf("%d.%s.json", roles.Targets(Targets).Signed.Version, name)
			err = roles.Targets(Targets).ToFile(filepath.Join(config.metadataDir, filename), true)
		case Snapshot:
			filename = fmt.Sprintf("%d.%s.json", roles.Snapshot().Signed.Version, name)
			err = roles.Snapshot().ToFile(filepath.Join(config.metadataDir, filename), true)
		case Timestamp:
			filename = fmt.Sprintf("%s.json", name)
			err = roles.Timestamp().ToFile(filepath.Join(config.metadataDir, filename), true)
		}

		if err != nil {
			for _, path := range succeededWrites {
				filesystem.Remove(path)
			}
			slog.ErrorContext(ctx, "fail to save metadata to file", slog.Any("error", err), slog.String("role", name))
			slog.InfoContext(ctx, "all generated metadata files removed")
			return fmt.Errorf("fail to save metadata to file\n\terror: %w", err)
		}
		succeededWrites = append(succeededWrites, filepath.Join(config.metadataDir, filename))
	}
	return nil
}
