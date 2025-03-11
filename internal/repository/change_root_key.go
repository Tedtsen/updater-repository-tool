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

func changeRootKey(config configChangeRootKey) error {
	// Append context to logger
	ctx := logging.AppendCtx(context.Background(), slog.Group("config",
		slog.String("metadata_dir", config.metadataDir),
		slog.String("action", config.action),
		slog.String("priv_keypath", config.privkeyFilepath),
		slog.String("input_priv_keypath", config.inputPrivkeyFilepath),
		// slog.String("repl_priv_keypath", config.replacementPrivkeyFilepath),
		slog.Int("expire", int(config.expireIn)),
		slog.Int("threshold", int(config.threshold)),
	))

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
	// if roles.Root().Signed.Roles[Root].Threshold == 1 && config.action == ChangeRootKeyActionReplace {
	// 	slog.ErrorContext(ctx, "replacing sole key is not allowed, please split into 2 steps i.e. add-and-remove")
	// 	return fmt.Errorf("replacing sole key is not allowed, please split into 2 steps i.e. add-and-remove")
	// }

	// Load root private key
	bytes, err := filesystem.ReadBytesFromFile(config.privkeyFilepath)
	if err != nil {
		slog.ErrorContext(ctx, "fail to read bytes from root private key file", slog.Any("error", err))
		return fmt.Errorf("fail to read bytes from root private key file: %w", err)
	}
	rootPrivkey, err := cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
	if err != nil {
		slog.ErrorContext(ctx, "fail to parse key from root private pem string", slog.Any("error", err))
		return fmt.Errorf("fail to parse key from root private pem string: %w", err)
	}

	// replPrivkey := &rsa.PrivateKey{}
	newPrivkey := &rsa.PrivateKey{}
	switch config.action {
	case ChangeRootKeyActionAdd:
		// Load new private key
		bytes, err = filesystem.ReadBytesFromFile(config.inputPrivkeyFilepath)
		if err != nil {
			slog.ErrorContext(ctx, "fail to read bytes from new private key file", slog.Any("error", err))
			return fmt.Errorf("fail to read bytes from new private key file: %w", err)
		}
		newPrivkey, err = cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
		if err != nil {
			slog.ErrorContext(ctx, "fail to parse key from private pem string", slog.Any("error", err))
			return fmt.Errorf("fail to parse key from new private pem string: %w", err)
		}
		// Init priv key metadata
		metaPubkey, err := metadata.KeyFromPublicKey(newPrivkey.Public())
		if err != nil {
			slog.ErrorContext(ctx, err.Error())
			return err
		}
		// Check duplicate
		if slices.Contains(roles.Root().Signed.Roles[Root].KeyIDs, metaPubkey.ID()) {
			slog.ErrorContext(ctx, "fail to add key, key was already added", slog.String("pubkey_ID", metaPubkey.ID()))
			return fmt.Errorf("fail to add key, key was already added\n\tpubkey id: %s", metaPubkey.ID())
		}
		// Add key to role
		if addErr := roles.Root().Signed.AddKey(metaPubkey, Root); addErr != nil {
			slog.ErrorContext(ctx, "fail to add key", slog.Any("error", addErr), slog.String("pubkey_ID", metaPubkey.ID()))
			return fmt.Errorf("fail to add key: %w", addErr)
		}
		// roles.Root().Signed.Roles[Root].Threshold += 1
	case ChangeRootKeyActionRemove:
		// Load info of key to be removed
		bytes, err = filesystem.ReadBytesFromFile(config.inputPrivkeyFilepath)
		if err != nil {
			slog.ErrorContext(ctx, "fail to read bytes from private key file", slog.Any("error", err))
			return fmt.Errorf("fail to read bytes from private key file: %w", err)
		}
		// Try to parse as private key, then as public key
		inputPrivkey, inputPubkey, isPub, err := tryParseAsPrivateThenPublic(ctx, bytes)
		if err != nil {
			slog.ErrorContext(ctx, err.Error())
			return err
		}
		// Init pub key metadata
		k := &rsa.PublicKey{}
		if isPub {
			k = inputPubkey
		} else {
			k = &inputPrivkey.PublicKey
		}
		metaPubkey, err := metadata.KeyFromPublicKey(k)
		if err != nil {
			slog.ErrorContext(ctx, err.Error())
			return err
		}
		// roles.Root().Signed.Roles[Root].Threshold -= 1
		// if roles.Root().Signed.Roles[Root].Threshold == 0 {
		// 	slog.ErrorContext(ctx, "fail to revoke key, threshold cannot be lower than 1", slog.String("pubkey_ID", metaPubkey.ID()))
		// 	return fmt.Errorf("fail to revoke key, threshold cannot be lower than 1")
		// }
		if revokeErr := roles.Root().Signed.RevokeKey(metaPubkey.ID(), Root); revokeErr != nil {
			slog.ErrorContext(ctx, "fail to revoke key", slog.Any("error", revokeErr), slog.String("pubkey_ID", metaPubkey.ID()))
			return fmt.Errorf("fail to revoke key: %w", revokeErr)
		}
		// case ChangeRootKeyActionReplace:
		// 	// Load replacement private key
		// 	bytes, err = filesystem.ReadBytesFromFile(config.replacementPrivkeyFilepath)
		// 	if err != nil {
		// 		slog.ErrorContext(ctx, "fail to read bytes from new private key file", slog.Any("error", err))
		// 		return fmt.Errorf("fail to read bytes from new private key file: %w", err)
		// 	}
		// 	replPrivkey, err = cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
		// 	if err != nil {
		// 		slog.ErrorContext(ctx, "fail to parse key from private pem string", slog.Any("error", err))
		// 		return fmt.Errorf("fail to parse key from new private pem string: %w", err)
		// 	}
		// 	// Init new pub key metadata
		// 	metaNewRootkey, err := metadata.KeyFromPublicKey(replPrivkey.Public())
		// 	if err != nil {
		// 		slog.ErrorContext(ctx, "fail to init new key metadata", slog.Any("error", err))
		// 		return fmt.Errorf("fail to init new key metadata: %w", err)
		// 	}

		// 	// Load key to be replaced
		// 	bytes, err = filesystem.ReadBytesFromFile(config.inputPrivkeyFilepath)
		// 	if err != nil {
		// 		slog.ErrorContext(ctx, "fail to read bytes from private key file", slog.Any("error", err))
		// 		return fmt.Errorf("fail to read bytes from private key file: %w", err)
		// 	}
		// 	// Try to parse as private key, then as public key
		// 	oldPrivkey, oldPubkey, isPub, err := tryParseAsPrivateThenPublic(ctx, bytes)
		// 	if err != nil {
		// 		slog.ErrorContext(ctx, err.Error())
		// 		return err
		// 	}
		// 	// Init old pub key metadata
		// 	k := &rsa.PublicKey{}
		// 	if isPub {
		// 		k = oldPubkey
		// 	} else {
		// 		k = &oldPrivkey.PublicKey
		// 	}
		// 	metaOldRootkey, err := metadata.KeyFromPublicKey(k)
		// 	if err != nil {
		// 		slog.ErrorContext(ctx, "fail to init old key metadata", slog.Any("error", err))
		// 		return fmt.Errorf("fail to init old key metadata: %w", err)
		// 	}

		// 	// Revoke old key
		// 	if revokeErr := roles.Root().Signed.RevokeKey(metaOldRootkey.ID(), Root); revokeErr != nil {
		// 		slog.ErrorContext(ctx, "fail to revoke key", slog.Any("error", revokeErr), slog.String("pubkey_ID", metaOldRootkey.ID()))
		// 		return fmt.Errorf("fail to revoke key: %w", revokeErr)
		// 	}
		// 	// Add new replacement key
		// 	if addErr := roles.Root().Signed.AddKey(metaNewRootkey, Root); addErr != nil {
		// 		slog.ErrorContext(ctx, "fail to add key", slog.Any("error", addErr), slog.String("pubkey_ID", metaNewRootkey.ID()))
		// 		return fmt.Errorf("fail to add key: %w", addErr)
		// 	}
	}

	// Clone previous old root before modification
	// previousRoot := roles.Root()

	// Increase root metadata file version, change expiration date and threshold
	roles.Root().Signed.Version += 1
	roles.Root().Signed.Expires = datetime.ExpireIn(int(config.expireIn))
	roles.Root().Signed.Roles[Root].Threshold = int(config.threshold)
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
	// replSig := &metadata.Signature{}
	newSig := &metadata.Signature{}
	/* if config.action == ChangeRootKeyActionReplace {
	// 	replSigner, err := signature.LoadSigner(replPrivkey, crypto.SHA256)
	// 	if err != nil {
	// 		slog.ErrorContext(ctx, "fail to load signer for root private key", slog.Any("error", err))
	// 		return fmt.Errorf("fail to load signer for root private key: %w", err)
	// 	}
	// 	replSig, err = roles.Root().Sign(replSigner)
	// 	if err != nil {
	// 		slog.ErrorContext(ctx, "fail to sign root metadata file with replacement key", slog.Any("error", err))
	// 		return fmt.Errorf("fail to sign root metadata file with replacement key: %w", err)
	// 	}
	 } else */if config.action == ChangeRootKeyActionAdd {
		newSigner, err := signature.LoadSigner(newPrivkey, crypto.SHA256)
		if err != nil {
			slog.ErrorContext(ctx, "fail to load signer for root private key", slog.Any("error", err))
			return fmt.Errorf("fail to load signer for root private key: %w", err)
		}
		newSig, err = roles.Root().Sign(newSigner)
		if err != nil {
			slog.ErrorContext(ctx, "fail to sign root metadata file with new key", slog.Any("error", err))
			return fmt.Errorf("fail to sign root metadata file with new key: %w", err)
		}
	}

	// Verify if the correct root private key is used to sign
	if !slices.Contains(roles.Root().Signed.Roles[Root].KeyIDs, sig.KeyID) {
		slog.ErrorContext(ctx, "unrecognized key is used to sign")
		return fmt.Errorf("unrecognized key is used to sign")
	}
	/*if config.action == ChangeRootKeyActionReplace {
		if !slices.Contains(roles.Root().Signed.Roles[Root].KeyIDs, replSig.KeyID) {
			slog.ErrorContext(ctx, "unrecognized replacement key is used to sign")
			return fmt.Errorf("unrecognized replacement key is used to sign")
		}
	} else */if config.action == ChangeRootKeyActionAdd {
		if !slices.Contains(roles.Root().Signed.Roles[Root].KeyIDs, newSig.KeyID) {
			slog.ErrorContext(ctx, "unrecognized new key is used to sign")
			return fmt.Errorf("unrecognized new key is used to sign")
		}
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
	fmt.Println("FILENAME", filename)
	err = roles.Root().ToFile(filepath.Join(config.metadataDir, filename), true)
	if err != nil {
		slog.ErrorContext(ctx, "fail to write root metadata to file", slog.Any("error", err))
		return fmt.Errorf("fail to write root metadata to file: %w", err)
	}
	slog.InfoContext(ctx, "Written to file")

	return nil
}

func tryParseAsPrivateThenPublic(ctx context.Context, bs []byte) (*rsa.PrivateKey, *rsa.PublicKey, bool, error) {
	isPub := false
	pubkey := &rsa.PublicKey{}
	privkey, err := cryptography.ParseRsaPrivateKeyFromPemStr(string(bs))
	if err != nil {
		slog.ErrorContext(ctx, "fail to parse key from role private pem string", slog.Any("error", err))
		slog.InfoContext(ctx, "Trying to parse as public key")
		pubkey, err = cryptography.ParseRsaPublicKeyFromPemStr(string(bs))
		if err != nil {
			slog.ErrorContext(ctx, "fail to parse key from public pem string", slog.Any("error", err))
			return nil, nil, false, fmt.Errorf("fail to parse key from public pem string: %w", err)
		}
		isPub = true
	}
	return privkey, pubkey, isPub, nil
}
