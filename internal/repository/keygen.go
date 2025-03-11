package repository

import (
	"fmt"
	"path/filepath"

	"see_updater/internal/pkg/cryptography"
	"see_updater/internal/pkg/filesystem"
)

func generateRsaKeypairPEM(config configKeygen) error {
	privKey, pubKey := cryptography.GenerateRsaKeyPair(config.bitLength)
	privKeyPemStr := cryptography.ExportRsaPrivateKeyAsPemStr(privKey)
	pubKeyPemStr, _ := cryptography.ExportRsaPublicKeyAsPemStr(pubKey)

	_, err := filesystem.IsDirWritable(config.outputDir)
	if err != nil {
		return err
	}

	privKeypath := filepath.Join(config.outputDir, config.privkeyFilename)
	err = filesystem.WriteStringToFile(privKeypath, privKeyPemStr)
	if err != nil {
		return err
	}
	fmt.Printf("Private key written to: %s", privKeypath)

	pubKeypath := filepath.Join(config.outputDir, config.pubkeyFilename)
	err = filesystem.WriteStringToFile(pubKeypath, pubKeyPemStr)
	if err != nil {
		return err
	}
	fmt.Printf("Public key written to: %s", pubKeypath)

	return nil
}
