package repository

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"path/filepath"

	"see_updater/internal/pkg/cryptography"
	"see_updater/internal/pkg/datetime"
	"see_updater/internal/pkg/filesystem"
	"see_updater/internal/pkg/logging"

	// "github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/repository"
)

// Reference: https://github.com/theupdateframework/go-tuf/blob/master/examples/repository/basic_repository.go
func initRepo(config configInit) error {
	// Append context to logger
	ctx := logging.AppendCtx(context.Background(), slog.Group("config",
		slog.String("repository_dir", config.repositoryDir),
		slog.String("output_dir", config.outputDir),
		slog.String("root_key_filepaths", config.rootPrivkeyFilepathsRaw),
		slog.String("targets_key_filepaths", config.targetsPrivkeyFilepathsRaw),
		slog.String("snapshot_key_filepaths", config.snapshotPrivkeyFilepathsRaw),
		slog.String("timestamp_key_filepaths", config.timestampPrivkeyFilepathsRaw),
		slog.Int("root_threshold", int(config.rootThreshhold)),
		slog.Int("targets_threshold", int(config.targetsThreshold)),
		slog.Int("snapshot_threshold", int(config.snapshotThreshold)),
		slog.Int("timestamp_threshold", int(config.timestampThreshold)),
		slog.Int("expire_in", int(config.expireIn)),
	))

	_, err := filesystem.IsDirWritable(config.outputDir)
	if err != nil {
		slog.WarnContext(ctx, "output dir for metadata files is not writable or does not exist", slog.Any("error", err), slog.String("path", config.outputDir))
		slog.InfoContext(ctx, fmt.Sprintf("Trying to make new dir at path %s", config.outputDir))
		if err = filesystem.MakeNewDir(config.outputDir); err != nil {
			slog.ErrorContext(ctx, "fail to make new dir at path", slog.Any("error", err), slog.String("path", config.outputDir))
			return fmt.Errorf("output dir for metadata files is not writable or does not exist, fail to make new dir: %w", err)
		}
	}

	roles := repository.New()

	targets := metadata.Targets(datetime.ExpireIn(int(config.expireIn)))
	roles.SetTargets(Targets, targets)
	snapshot := metadata.Snapshot(datetime.ExpireIn(int(config.expireIn)))
	roles.SetSnapshot(snapshot)
	timestamp := metadata.Timestamp(datetime.ExpireIn(int(config.expireIn)))
	roles.SetTimestamp(timestamp)
	root := metadata.Root(datetime.ExpireIn(int(config.expireIn)))
	roles.SetRoot(root)

	// Set Targets
	// Full filepath: C:/Users/User/Project/file.txt
	// Local filepath:  Project/file.txt
	targetLocalFilepaths, targetFullFilepaths, err := filesystem.GetAllFilepathsInDir(config.repositoryDir)
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		return err
	}
	for i, targetFullFilepath := range targetFullFilepaths {
		slog.DebugContext(ctx, "generating target file info for file", slog.String("filepath", targetLocalFilepaths[i]))
		targetFileInfo, err := metadata.TargetFile().FromFile(targetFullFilepath)
		if err != nil {
			slog.ErrorContext(ctx, "fail to generate target file info for file", slog.Any("error", err), slog.String("filepath", targetFullFilepath))
			return fmt.Errorf("fail to generate target file info for file: %s\n\terror: %w", targetFullFilepath, err)
		}
		roles.Targets(Targets).Signed.Targets[targetLocalFilepaths[i]] = targetFileInfo
	}

	// Read root private RSA rolesKeys (public key can be derived from private key)
	rolesKeys, err := readRolesPrivkeysFromFilepaths(map[string][]string{
		Root:      config.rolesPrivkeyFilepaths[Root],
		Targets:   config.rolesPrivkeyFilepaths[Targets],
		Snapshot:  config.rolesPrivkeyFilepaths[Snapshot],
		Timestamp: config.rolesPrivkeyFilepaths[Timestamp],
	})
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		return (err)
	}

	// Record public keys info in root metadata file
	for _, name := range getRoles() {
		for _, key := range rolesKeys[name] {
			pubkey, err := metadata.KeyFromPublicKey(key.Public())
			if err != nil {
				slog.ErrorContext(ctx, "fail to convert private key to public key", slog.Any("error", err), slog.String("role", name))
				return fmt.Errorf("fail to convert private key to public key for role: %s\n\terror: %w", name, err)
			}
			err = roles.Root().Signed.AddKey(pubkey, name)
			if err != nil {
				slog.ErrorContext(ctx, "fail to add key", slog.Any("error", err), slog.String("role", name))
				return fmt.Errorf("fail to add key to role: %s\n\terror: %w", name, err)
			}
		}
	}

	// Set roles signature threshold
	thresholds := map[string]uint8{
		Root:      config.rootThreshhold,
		Targets:   config.targetsThreshold,
		Snapshot:  config.snapshotThreshold,
		Timestamp: config.timestampThreshold,
	}
	for name, threshold := range thresholds {
		roles.Root().Signed.Roles[name].Threshold = int(threshold)
	}

	// Sign metadata files for each respective role
	for _, name := range getRoles() {
		for _, key := range rolesKeys[name] {
			signer, err := signature.LoadSigner(key, crypto.SHA256)
			if err != nil {
				slog.ErrorContext(ctx, "fail to load signer for private key", slog.Any("error", err), slog.String("role", name))
				return fmt.Errorf("fail to load signer for private key of role: %s\n\terror: %w", name, err)
			}
			switch name {
			case Targets:
				_, err = roles.Targets(Targets).Sign(signer)
			case Snapshot:
				_, err = roles.Snapshot().Sign(signer)
			case Timestamp:
				_, err = roles.Timestamp().Sign(signer)
			case Root:
				_, err = roles.Root().Sign(signer)
			}
			if err != nil {
				slog.ErrorContext(ctx, "fail to sign metadata file", slog.Any("error", err), slog.String("role", name))
				return fmt.Errorf("fail to sign metadata file for role: %s\n\terror: %w", name, err)
			}
		}
	}

	// Verify the metadata files are signed correctly (reaching threshold)
	for _, name := range getRoles() {
		switch name {
		case Targets:
			if err = roles.Root().VerifyDelegate(Targets, roles.Targets(Targets)); err != nil {
				slog.WarnContext(ctx, "fail to verify metadata", slog.Any("error", err), slog.String("role", name))
			}
		case Snapshot:
			if err = roles.Root().VerifyDelegate(Snapshot, roles.Snapshot()); err != nil {
				slog.WarnContext(ctx, "fail to verify metadata", slog.Any("error", err), slog.String("role", name))
			}
		case Timestamp:
			if err = roles.Root().VerifyDelegate(Timestamp, roles.Timestamp()); err != nil {
				slog.WarnContext(ctx, "fail to verify metadata", slog.Any("error", err), slog.String("role", name))
			}
		case Root:
			if err = roles.Root().VerifyDelegate(Root, roles.Root()); err != nil {
				slog.WarnContext(ctx, "fail to verify metadata", slog.Any("error", err), slog.String("role", name))
			}
		}
	}

	// Attempt write
	outputDir := config.outputDir
	// Write metadata files
	// TODO This write operation will overwrite the first versions of metadata files if they exist,
	// prompt warning if the output metadata directory is not empty??
	succeededWrites := []string{} // To remove written files in case of error
	for _, name := range []string{Targets, Snapshot, Timestamp, Root} {
		filename := ""
		switch name {
		case Targets:
			// roles.Targets(Targets).Sign()
			filename := fmt.Sprintf("%d.%s.json", roles.Targets(Targets).Signed.Version, name)
			err = roles.Targets(Targets).ToFile(filepath.Join(outputDir, filename), true)
		case Snapshot:
			filename := fmt.Sprintf("%d.%s.json", roles.Snapshot().Signed.Version, name)
			err = roles.Snapshot().ToFile(filepath.Join(outputDir, filename), true)
		case Timestamp:
			filename := fmt.Sprintf("%s.json", name)
			err = roles.Timestamp().ToFile(filepath.Join(outputDir, filename), true)
		case Root:
			filename := fmt.Sprintf("%d.%s.json", roles.Root().Signed.Version, name)
			err = roles.Root().ToFile(filepath.Join(outputDir, filename), true)
		}
		if err != nil {
			for _, path := range succeededWrites {
				filesystem.Remove(path)
			}
			slog.ErrorContext(ctx, "fail to save metadata to file", slog.Any("error", err), slog.String("role", name))
			slog.InfoContext(ctx, "all generated metadata files removed")
			return fmt.Errorf("fail to save metadata to file\n\terror: %w", err)
		}
		succeededWrites = append(succeededWrites, filepath.Join(outputDir, filename))
	}

	return nil
}

func readRolesPrivkeysFromFilepaths(pathsMap map[string][]string) (map[string][]*rsa.PrivateKey, error) {
	keys := map[string][]*rsa.PrivateKey{}
	for role, paths := range pathsMap {
		for _, path := range paths {
			privkeyBytes, err := filesystem.ReadBytesFromFile(path)
			if err != nil {
				return nil, fmt.Errorf("fail to read private key bytes from file: %s\n\terror: %w", path, err)
			}
			privkey, err := cryptography.ParseRsaPrivateKeyFromPemStr(string(privkeyBytes))
			if err != nil {
				return nil, fmt.Errorf("fail to parse private key from pem string\n\terror: %w", err)
			}
			keys[role] = append(keys[role], privkey)
		}
	}
	return keys, nil
}
