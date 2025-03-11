package repository

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"

	"see_updater/internal/pkg/cryptography"
	"see_updater/internal/pkg/datetime"
	"see_updater/internal/pkg/filesystem"
	"see_updater/internal/pkg/logging"
	"see_updater/internal/pkg/metahelper"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/repository"
)

func changeThreshold(config configChangeThreshold) error {
	// Append context to logger
	ctx := logging.AppendCtx(context.Background(), slog.Group("config",
		slog.String("metadata_dir", config.metadataDir),
		slog.String("action", config.action),
		slog.String("role", config.role),
		slog.String("role_priv_keypath", config.rolePrivkeyFilepath),
		slog.String("root_priv_keypath", config.rootPrivkeyFilepath),
	))

	// Load root private key
	bytes, err := filesystem.ReadBytesFromFile(config.rootPrivkeyFilepath)
	if err != nil {
		slog.ErrorContext(ctx, "fail to read bytes from root private key file", slog.Any("error", err))
		return fmt.Errorf("fail to read bytes from root private key file: %w", err)
	}
	rootPrivkey, err := cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
	if err != nil {
		slog.ErrorContext(ctx, "fail to parse key from root private pem string", slog.Any("error", err))
		return fmt.Errorf("fail to parse key from root private pem string: %w", err)
	}

	// Load role private key for `add` operation
	// Load role private OR public key for `reduce` operation
	isPub := false
	bytes, err = filesystem.ReadBytesFromFile(config.rolePrivkeyFilepath)
	if err != nil {
		slog.ErrorContext(ctx, "fail to read bytes from role private key file", slog.Any("error", err), slog.String("role", config.role))
		return fmt.Errorf("fail to read bytes from role private key file: %w", err)
	}
	// Try to parse as private key
	rolePubkey := &rsa.PublicKey{}
	rolePrivkey, err := cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
	if err != nil {
		slog.ErrorContext(ctx, "fail to parse key from role private pem string", slog.Any("error", err), slog.String("role", config.role))
		if config.action == ChangeThresholdActionAdd {
			return fmt.Errorf("fail to parse key from role private pem string: %w", err)
		} else if config.action == ChangeThresholdActionReduce {
			// If `reduce`, try to parse as public key
			slog.InfoContext(ctx, "Trying to parse as public key for `reduce` operation")
			rolePubkey, err = cryptography.ParseRsaPublicKeyFromPemStr(string(bytes))
			if err != nil {
				slog.ErrorContext(ctx, "fail to parse key from role public pem string", slog.Any("error", err), slog.String("role", config.role))
				return fmt.Errorf("fail to parse key from role public pem string: %w", err)
			}
			isPub = true
		}
	}

	// Load root metadata file for verification purpose
	roles := repository.New()
	root := metadata.Root(datetime.ExpireIn(DefaultExpireIn))
	roles.SetRoot(root)
	rootMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Root)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata filepaths", slog.Any("error", err))
		return fmt.Errorf("fail to load metadata filepaths: %w", err)
	}
	_, err = roles.Root().FromFile(rootMetadataFilepaths[len(rootMetadataFilepaths)-1])
	if err != nil {
		slog.ErrorContext(ctx, "fail to load metadata file", slog.Any("error", err))
		return fmt.Errorf("fail to load metadata file: %w", err)
	}
	// Verify the old root metadata file has been signed (reached threshold)
	if err = roles.Root().VerifyDelegate(Root, roles.Root()); err != nil {
		slog.ErrorContext(ctx, "old root metadata has inadequate signatures", slog.Any("error", err))
		return fmt.Errorf("old root metadata has inadequate signatures: %w", err)
	}

	// Change threshold
	k := &rsa.PublicKey{}
	if isPub {
		k = rolePubkey
	} else {
		k = &rolePrivkey.PublicKey
	}
	metaPubkey, err := metadata.KeyFromPublicKey(k)
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		return err
	}
	switch config.action {
	case ChangeThresholdActionAdd:
		roles.Root().Signed.Roles[config.role].Threshold += 1
		// Check duplicate
		if slices.Contains(roles.Root().Signed.Roles[config.role].KeyIDs, metaPubkey.ID()) {
			slog.ErrorContext(ctx, "fail to add key, key was already added", slog.String("pubkey_ID", metaPubkey.ID()))
			return fmt.Errorf("fail to add key, key was already added\n\tpubkey id: %s", metaPubkey.ID())
		}
		// Add key to role
		if addErr := roles.Root().Signed.AddKey(metaPubkey, config.role); addErr != nil {
			slog.ErrorContext(ctx, "fail to add key", slog.Any("error", addErr), slog.String("pubkey_ID", metaPubkey.ID()))
			return fmt.Errorf("fail to add key: %w", addErr)
		}
	case ChangeThresholdActionReduce:
		roles.Root().Signed.Roles[config.role].Threshold -= 1
		if roles.Root().Signed.Roles[config.role].Threshold == 0 {
			slog.ErrorContext(ctx, "fail to revoke key, threshold cannot be lower than 1", slog.String("pubkey_ID", metaPubkey.ID()))
			return fmt.Errorf("fail to revoke key, threshold cannot be lower than 1")
		}
		if revokeErr := roles.Root().Signed.RevokeKey(metaPubkey.ID(), config.role); revokeErr != nil {
			slog.ErrorContext(ctx, "fail to revoke key", slog.Any("error", revokeErr), slog.String("pubkey_ID", metaPubkey.ID()))
			return fmt.Errorf("fail to revoke key: %w", revokeErr)
		}
	}

	// Increase root metadata file version
	roles.Root().Signed.Version += 1
	roles.Root().ClearSignatures()

	// Load signer and sign
	signer, err := signature.LoadSigner(rootPrivkey, crypto.SHA256)
	if err != nil {
		slog.ErrorContext(ctx, "fail to load signer for root private key", slog.Any("error", err))
		return fmt.Errorf("fail to load signer for root private key: %w", err)
	}
	sig, err := roles.Root().Sign(signer)
	if err != nil {
		slog.ErrorContext(ctx, "fail to sign root metadata file", slog.Any("error", err))
		return fmt.Errorf("fail to sign root metadata file: %w", err)
	}

	// Verify if the correct root private key is used to sign
	if !slices.Contains(roles.Root().Signed.Roles[Root].KeyIDs, sig.KeyID) {
		slog.ErrorContext(ctx, "unrecognized key is used to sign")
		return fmt.Errorf("unrecognized key is used to sign")
	}

	// Verify the root metadata file is signed correctly (reaching threshold)
	if err = roles.Root().VerifyDelegate(Root, roles.Root()); err != nil {
		slog.WarnContext(ctx, "fail to verify root", slog.Any("error", err))
	}

	// Attempt write
	_, err = filesystem.IsDirWritable(config.metadataDir)
	if err != nil {
		slog.ErrorContext(ctx, "metadata directory is not writable", slog.Any("error", err))
		return fmt.Errorf("metadata directory is not writable: %w", err)
	}
	filename := fmt.Sprintf("%d.%s.json", roles.Root().Signed.Version, Root)
	err = roles.Root().ToFile(filepath.Join(config.metadataDir, filename), true)
	if err != nil {
		slog.ErrorContext(ctx, "fail to write root metadata to file", slog.Any("error", err))
		return fmt.Errorf("fail to write root metadata to file: %w", err)
	}
	slog.InfoContext(ctx, "Written to file")

	return nil
}
