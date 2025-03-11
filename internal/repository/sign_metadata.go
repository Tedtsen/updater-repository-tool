package repository

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"

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

func signMetadata(config configSign) error {
	// Append context to logger
	ctx := logging.AppendCtx(context.Background(), slog.Group("config",
		slog.String("metadata_dir", config.metadataDir),
		slog.String("role", config.role),
		slog.String("priv_keypath", config.privkeyFilepath),
	))

	// Load private key
	bytes, err := filesystem.ReadBytesFromFile(config.privkeyFilepath)
	if err != nil {
		slog.ErrorContext(ctx, "fail to read bytes from private key file", slog.Any("error", err))
		return fmt.Errorf("fail to read bytes from private key file: %w", err)
	}
	key, err := cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
	if err != nil {
		slog.ErrorContext(ctx, "fail to parse key from private pem string", slog.Any("error", err))
		return fmt.Errorf("fail to parse key from private pem string: %w", err)
	}
	signer, err := signature.LoadSigner(key, crypto.SHA256)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load signer for private key", slog.Any("error", err))
		return fmt.Errorf("fail to load signer for private key: %w", err)
	}

	// Load root metadata file for verification purpose
	roles := repository.New()
	root := metadata.Root(datetime.ExpireIn(7))
	roles.SetRoot(root)

	rootMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Root)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata filepaths", slog.Any("error", err), slog.String("role", Root))
		return fmt.Errorf("fail to load metadata filepaths: %w", err)
	}
	_, err = roles.Root().FromFile(rootMetadataFilepaths[len(rootMetadataFilepaths)-1])
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata from file", slog.Any("error", err), slog.String("role", Root))
		return fmt.Errorf("fail to load metadata from file: %w", err)
	}

	// Load roles metadata from file
	roleMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, config.role)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata filepaths", slog.Any("error", err), slog.String("role", config.role))
		return fmt.Errorf("fail to load metadata filepaths: %w", err)
	}
	var loadErr error
	switch config.role {
	case Targets:
		targets := metadata.Targets(datetime.ExpireIn(7))
		roles.SetTargets(Targets, targets)
		_, loadErr = roles.Targets(Targets).FromFile(roleMetadataFilepaths[len(roleMetadataFilepaths)-1])
	case Snapshot:
		snapshot := metadata.Snapshot(datetime.ExpireIn(7))
		roles.SetSnapshot(snapshot)
		_, loadErr = roles.Snapshot().FromFile(roleMetadataFilepaths[len(roleMetadataFilepaths)-1])
	case Timestamp:
		timestamp := metadata.Timestamp(datetime.ExpireIn(7))
		roles.SetTimestamp(timestamp)
		_, loadErr = roles.Timestamp().FromFile(roleMetadataFilepaths[len(roleMetadataFilepaths)-1])
	case Root:
		root := metadata.Root(datetime.ExpireIn(7))
		roles.SetRoot(root)
		_, loadErr = roles.Root().FromFile(roleMetadataFilepaths[len(roleMetadataFilepaths)-1])

	}
	if loadErr != nil {
		slog.ErrorContext(ctx, "fail to load target metadata", slog.Any("error", loadErr), slog.String("role", config.role))
		return fmt.Errorf("fail to load target metadata for given role: %s\n\terror: %w", config.role, loadErr)
	}

	// Sign
	var signErr error
	var signature *metadata.Signature
	switch config.role {
	case Targets:
		signature, signErr = roles.Targets(Targets).Sign(signer)
	case Snapshot:
		signature, signErr = roles.Snapshot().Sign(signer)

	case Timestamp:
		signature, signErr = roles.Timestamp().Sign(signer)
	case Root:
		signature, signErr = roles.Root().Sign(signer)
	}
	if signErr != nil {
		slog.ErrorContext(ctx, "fail to sign target metadata", slog.Any("error", signErr), slog.String("role", config.role))
		return fmt.Errorf("fail to sign target metadata for given role: %s\n\terror: %w", config.role, signErr)
	}

	// Check duplicate signature (old signature == new signature)
	var dupErr error
	switch config.role {
	case Targets:
		sigCount := map[string]int{}
		for _, sig := range roles.Targets(Targets).Signatures {
			sigCount[sig.KeyID] += 1
			if sigCount[sig.KeyID] > 1 {
				dupErr = fmt.Errorf("key count: %d, key id: %s", sigCount[sig.KeyID], sig.KeyID)
				slog.ErrorContext(ctx, "duplicate signature found", slog.Any("error", dupErr), slog.String("role", config.role),
					slog.Int("signature_count", sigCount[sig.KeyID]), slog.String("key_id", sig.KeyID))
			}
		}
	case Snapshot:
		sigCount := map[string]int{}
		for _, sig := range roles.Snapshot().Signatures {
			sigCount[sig.KeyID] += 1
			if sigCount[sig.KeyID] > 1 {
				dupErr = fmt.Errorf("key count: %d, key id: %s", sigCount[sig.KeyID], sig.KeyID)
				slog.ErrorContext(ctx, "duplicate signature found", slog.Any("error", dupErr), slog.String("role", config.role),
					slog.Int("signature_count", sigCount[sig.KeyID]), slog.String("key_id", sig.KeyID))
			}
		}
	case Timestamp:
		sigCount := map[string]int{}
		for _, sig := range roles.Timestamp().Signatures {
			sigCount[sig.KeyID] += 1
			if sigCount[sig.KeyID] > 1 {
				dupErr = fmt.Errorf("key count: %d, key id: %s", sigCount[sig.KeyID], sig.KeyID)
				slog.ErrorContext(ctx, "duplicate signature found", slog.Any("error", dupErr), slog.String("role", config.role),
					slog.Int("signature_count", sigCount[sig.KeyID]), slog.String("key_id", sig.KeyID))
			}
		}
	case Root:
		sigCount := map[string]int{}
		for _, sig := range roles.Root().Signatures {
			sigCount[sig.KeyID] += 1
			if sigCount[sig.KeyID] > 1 {
				dupErr = fmt.Errorf("key count: %d, key id: %s", sigCount[sig.KeyID], sig.KeyID)
				slog.ErrorContext(ctx, "duplicate signature found", slog.Any("error", dupErr), slog.String("role", config.role),
					slog.Int("signature_count", sigCount[sig.KeyID]), slog.String("key_id", sig.KeyID))
			}
		}
	}
	if dupErr != nil {
		// TODO duplicate can be signed again to solve the case where (some manual edit in metadata file causing verification to fail, prompting signature not reaching threshold, but the keyid was already used to sign and cant resign the manually edited version)
		return fmt.Errorf("duplicate signature found for given role: %s\n\terror: %w", config.role, dupErr)
	}

	// Verify signature and ask for confirmation
	var verErr error
	if !config.forced && !slices.Contains(roles.Root().Signed.Roles[config.role].KeyIDs, signature.KeyID) {
		slog.ErrorContext(ctx, "unrecognized key", slog.String("role", config.role), slog.String("key_filepath", config.privkeyFilepath))
		slog.Info("signing operation aborted")
		return fmt.Errorf("unrecognized key is used to sign role: %s, key filepath: %s", config.role, config.privkeyFilepath)
	}
	switch config.role {
	case Targets:
		verErr = roles.Root().VerifyDelegate(Targets, roles.Targets(Targets))
	case Snapshot:
		verErr = roles.Root().VerifyDelegate(Snapshot, roles.Snapshot())
	case Timestamp:
		verErr = roles.Root().VerifyDelegate(Timestamp, roles.Timestamp())
	case Root:
		verErr = roles.Root().VerifyDelegate(Root, roles.Root())
	}
	if verErr != nil {
		slog.Warn("fail to verify targets metadata signature", slog.Any("error", verErr), slog.String("role", config.role))
		fmt.Printf("fail to verify targets metadata signature for given role: %s\n\terror: %v\n", config.role, verErr)
		// Two scenarios:
		// 1. User used the RIGHT key to sign, but total RIGHT signature < threshold
		// 2. User used the WRONG key to sign, total RIGHT signature < threshold
		fmt.Println("Please perform additional signing to meet the threshold, program will now proceed to write the signature to the metadata file (irreversible)")
		if !cli.AskConfirmation(3) {
			fmt.Println("Operation aborted, no changes were made")
			return nil
		}
	}

	// Write
	var writeErr error
	var filename string
	switch config.role {
	case Targets:
		filename = fmt.Sprintf("%d.%s.json", roles.Targets(Targets).Signed.Version, config.role)
		writeErr = roles.Targets(Targets).ToFile(filepath.Join(config.metadataDir, filename), true)
	case Snapshot:
		filename = fmt.Sprintf("%d.%s.json", roles.Snapshot().Signed.Version, config.role)
		writeErr = roles.Snapshot().ToFile(filepath.Join(config.metadataDir, filename), true)
	case Timestamp:
		filename = fmt.Sprintf("%s.json", config.role)
		writeErr = roles.Timestamp().ToFile(filepath.Join(config.metadataDir, filename), true)
	case Root:
		filename = fmt.Sprintf("%d.%s.json", roles.Root().Signed.Version, config.role)
		writeErr = roles.Root().ToFile(filepath.Join(config.metadataDir, filename), true)
	}
	if writeErr != nil {
		slog.ErrorContext(ctx, "fail to write signed target metadata to file", slog.Any("error", writeErr),
			slog.String("role", config.role),
			slog.String("filepath", filepath.Join(config.metadataDir, filename)))
		return fmt.Errorf("fail to write signed target metadata to file: %s,for given role: %s\n\terror: %w",
			filepath.Join(config.metadataDir, filename), config.role, writeErr)
	}

	slog.Info("signing operation completed :D", slog.String("role", config.role),
		slog.String("key_filepath", config.privkeyFilepath),
		slog.String("output_filepath", filepath.Join(config.metadataDir, filename)))

	return nil
}
