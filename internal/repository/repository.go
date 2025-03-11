package repository

import (
	"fmt"
	"log/slog"
	"os"
	"see_updater/internal/pkg/logging"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	// "github.com/spf13/cobra/doc"
)

/* command configuration */
type configKeygen struct {
	outputDir       string
	privkeyFilename string
	pubkeyFilename  string
	bitLength       uint16
}
type configInit struct {
	repositoryDir           string
	outputDir               string
	rootPrivkeyFilepathsRaw string
	// rootPubkeyFilepathsRaw       string
	targetsPrivkeyFilepathsRaw string
	// targetsPubkeyFilepathsRaw    string
	snapshotPrivkeyFilepathsRaw string
	// snapshotPubkeyFilepathsRaw   string
	timestampPrivkeyFilepathsRaw string
	// timestampPubkeyFilepathsRaw  string
	rolesPrivkeyFilepaths map[string]([]string)
	rootThreshhold        uint8
	targetsThreshold      uint8
	snapshotThreshold     uint8
	timestampThreshold    uint8
	expireIn              uint16
}
type configUpdate struct {
	repositoryDir            string
	metadataDir              string
	targetsPrivkeyFilepath   string
	snapshotPrivkeyFilepath  string
	timestampPrivkeyFilepath string
	expireIn                 uint16
	askConfirmation          bool
}
type configSign struct {
	metadataDir     string
	role            string
	privkeyFilepath string
	forced          bool
}
type configChangeThreshold struct {
	metadataDir         string
	action              string // add/reduce
	role                string
	rootPrivkeyFilepath string
	rolePrivkeyFilepath string
}
type configVerify struct {
	repositoryDir string
	metadataDir   string
}
type configChangeRootKey struct {
	metadataDir                string
	action                     string // add/remove/replace
	privkeyFilepath            string
	replacementPrivkeyFilepath string // new replacement key
	inputPrivkeyFilepath       string // key to be added/removed
	expireIn                   uint16
	threshold                  uint16
}

/* command configuration */

// type repositoryMetadataGenerator struct {
// }

func NewCommand() *cobra.Command {
	// Init logger
	h := &logging.ContextHandler{Handler: slog.NewJSONHandler(os.Stdout, nil)}
	logger := slog.New(h)
	slog.SetDefault(logger)

	// Command to generate a RSA pem file
	configKeygen := configKeygen{
		bitLength: 4096,
	}
	cmdKeygen := &cobra.Command{
		Use:   KeygenVerb,
		Short: "Generate RSA keypair pem file (4096 bit)",
		Long:  "Generate RSA keypair pem file (4096 bit)",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("%s\n", "Running keygen command...")

			if configKeygen.privkeyFilename == configKeygen.pubkeyFilename {
				fmt.Fprintf(cmd.OutOrStdout(), "Encountered some issue: private and public filenames cannot be the same\n")
				fmt.Fprintln(cmd.OutOrStdout(), KeygenFailed)
				return
			}

			err := generateRsaKeypairPEM(configKeygen)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Encountered some issue: %v\n", err)
				fmt.Fprintln(cmd.OutOrStdout(), KeygenFailed)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), KeygenSucceeded)
			}
		},
	}
	// Bit-length of key is fixed at 4096-bit
	cmdKeygen.Flags().StringVarP(&configKeygen.outputDir, KeygenOutputDir, "d", "", "Directory for output key files (required)")
	cmdKeygen.Flags().StringVarP(&configKeygen.privkeyFilename, KeygenPrivkeyFilename, "v", "", "Private key filename (required)")
	cmdKeygen.Flags().StringVarP(&configKeygen.pubkeyFilename, KeygenPubkeyFilename, "b", "", "Public key filename (required)")
	cmdKeygen.MarkFlagRequired(KeygenOutputDir)
	cmdKeygen.MarkFlagsRequiredTogether(KeygenOutputDir, KeygenPrivkeyFilename, KeygenPubkeyFilename)

	// Command to initialize repository with new metadata files
	configInit := configInit{}
	cmdInit := &cobra.Command{
		Use:   InitVerb,
		Short: "Initialize repository with metadata files",
		Long:  "Initialize repository with metadata files",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("%s\n", "Running init command...")

			// Check if signature threshold for each role > 1,
			// if so then check if supplied paths are enough (path delimiter is ;)
			roles := getRoles()
			thresholds := map[string]uint8{
				Root:      configInit.rootThreshhold,
				Targets:   configInit.targetsThreshold,
				Snapshot:  configInit.snapshotThreshold,
				Timestamp: configInit.timestampThreshold,
			}
			keyFilepaths := map[string]string{
				Root:      configInit.rootPrivkeyFilepathsRaw,
				Targets:   configInit.targetsPrivkeyFilepathsRaw,
				Snapshot:  configInit.snapshotPrivkeyFilepathsRaw,
				Timestamp: configInit.timestampPrivkeyFilepathsRaw,
			}
			configInit.rolesPrivkeyFilepaths = make(map[string][]string)
			for _, name := range roles {
				configInit.rolesPrivkeyFilepaths[name] = strings.Split(keyFilepaths[name], ";")
				if int(thresholds[name]) == 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "Threshold must be greater than 0 for role: %s\n", name)
					return
				} else if int(thresholds[name]) != len(configInit.rolesPrivkeyFilepaths[name]) {
					fmt.Fprintf(cmd.OutOrStdout(), "Too few/many private key(s) provided for role: %s\n\twant: %d, have: %d\n",
						name, thresholds[name], len(configInit.rolesPrivkeyFilepaths[name]))
					fmt.Fprintln(cmd.OutOrStdout(), InitFailed)
					return
				}
			}

			err := initRepo(configInit)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Encountered some issue: %v\n", err)
				fmt.Fprintln(cmd.OutOrStdout(), InitFailed)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Metadata files written to: %s\n", configInit.outputDir)
				fmt.Fprintln(cmd.OutOrStdout(), InitSucceeded)

			}
		},
	}
	cmdInit.Flags().StringVarP(&configInit.repositoryDir, InitRepositoryDir, "d", "", "Directory containing target files (required)")
	cmdInit.Flags().StringVarP(&configInit.outputDir, InitOutputDir, "o", "", "Directory for output metadata files (required)")
	// Keypairs
	cmdInit.Flags().StringVarP(&configInit.rootPrivkeyFilepathsRaw, InitRootPrivkeyFilepath, "v", "", "Root private key filepath(s) (required)")
	cmdInit.Flags().StringVarP(&configInit.targetsPrivkeyFilepathsRaw, InitTargetsPrivkeyFilepath, "x", "", "Targets private key filepath(s) (required)")
	cmdInit.Flags().StringVarP(&configInit.snapshotPrivkeyFilepathsRaw, InitSnapshotPrivkeyFilepath, "p", "", "Snapshot private key filepath(s) (required)")
	cmdInit.Flags().StringVarP(&configInit.timestampPrivkeyFilepathsRaw, InitTimestampPrivkeyFilepath, "i", "", "Timestamp private key filepath(s) (required)")
	// Thresholds
	cmdInit.Flags().Uint8VarP(&configInit.rootThreshhold, InitRootThreshold, "r", 1, "Root key threshold (required)")
	cmdInit.Flags().Uint8VarP(&configInit.targetsThreshold, InitTargetsThreshold, "g", 1, "Targets key threshold (required)")
	cmdInit.Flags().Uint8VarP(&configInit.snapshotThreshold, InitSnapshotThreshold, "n", 1, "Snapshot key threshold (required)")
	cmdInit.Flags().Uint8VarP(&configInit.timestampThreshold, InitTimestampThreshold, "s", 1, "Timestamp key threshold (required)")
	cmdInit.Flags().Uint16VarP(&configInit.expireIn, InitExpire, "e", 365, "Metadata file expiration in days (required)")
	cmdInit.MarkFlagRequired(InitRepositoryDir)
	cmdInit.MarkFlagsRequiredTogether(InitRepositoryDir, InitOutputDir,
		InitRootPrivkeyFilepath, InitTargetsPrivkeyFilepath, InitSnapshotPrivkeyFilepath, InitTimestampPrivkeyFilepath,
		InitRootThreshold, InitTargetsThreshold, InitSnapshotThreshold, InitTimestampThreshold, InitExpire)

	// Command to update metadata files when new targets are added
	configUpdate := configUpdate{}
	cmdUpdate := &cobra.Command{
		Use:   UpdateVerb,
		Short: "Update repository with new metadata files",
		Long:  "Update repository with new metadata files, provide optional keys for targets/snapshot/timestamp roles to sign",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("%s\n", "Running update command...")

			// Allowed subsets of private keys
			// 1. (targets)
			// 2. (targets, snapshot)
			// 3. (targets, snapshot, timestamp)
			if len(configUpdate.timestampPrivkeyFilepath) > 0 {
				if len(configUpdate.snapshotPrivkeyFilepath) == 0 || len(configUpdate.targetsPrivkeyFilepath) == 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "Snapshot and targets private keys must be provided")
					fmt.Fprintln(cmd.OutOrStdout(), UpdateFailed)
					return
				}
			} else if len(configUpdate.snapshotPrivkeyFilepath) > 0 && len(configUpdate.targetsPrivkeyFilepath) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "Targets private key must be provided")
				fmt.Fprintln(cmd.OutOrStdout(), UpdateFailed)
				return
			}

			err := updateMetadata(configUpdate)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Encountered some issue: %v\n", err)
				fmt.Fprintln(cmd.OutOrStdout(), UpdateFailed)
				return
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Metadata files updated in dir: %s\n", configUpdate.metadataDir)
				fmt.Fprintln(cmd.OutOrStdout(), UpdateSucceeded)
			}
		},
	}
	cmdUpdate.Flags().StringVarP(&configUpdate.repositoryDir, UpdateRepositoryDir, "d", "", "Directory containing target files (required)")
	cmdUpdate.Flags().StringVarP(&configUpdate.metadataDir, UpdateMetadataDir, "m", "", "Directory containing metadata files (required)")
	cmdUpdate.Flags().StringVarP(&configUpdate.targetsPrivkeyFilepath, UpdateTargetsPrivkeyFilepath, "r", "", "Filepath of the private key for targets role (required)")
	cmdUpdate.Flags().StringVarP(&configUpdate.snapshotPrivkeyFilepath, UpdateSnapshotPrivkeyFilepath, "s", "", "Filepath of the private key for snapshot role (optional, but requires targets key)")
	cmdUpdate.Flags().StringVarP(&configUpdate.timestampPrivkeyFilepath, UpdateTimestampPrivkeyFilepath, "t", "", "Filepath of the private key for timestamp role (optional, but requires snapshot and targets keys)")
	cmdUpdate.Flags().Uint16VarP(&configUpdate.expireIn, UpdateExpire, "e", 365, "Metadata file expiration in days (required)")
	cmdUpdate.Flags().BoolVarP(&configUpdate.askConfirmation, UpdateAskConfirmation, "c", true, "Ask for confirmation before proceeding (optional)")
	cmdUpdate.MarkFlagRequired(UpdateRepositoryDir)
	cmdUpdate.MarkFlagsRequiredTogether(UpdateRepositoryDir, UpdateMetadataDir, UpdateTargetsPrivkeyFilepath, UpdateExpire)

	// Command to sign metadata file by role
	configSign := configSign{}
	cmdSign := &cobra.Command{
		Use:   SignVerb,
		Short: "Sign the metadata file by role",
		Long:  "Sign the metadata file by role",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Running sign command...")
			fmt.Printf("Signing metadata file as role: %s...\n", configSign.role)

			if !slices.Contains([]string{Targets, Snapshot, Timestamp, Root}, configSign.role) {
				fmt.Println("Invalid role provided, accepted: \"targets\", \"snapshot\", \"timestamp\", \"root\"")
				fmt.Fprintln(cmd.OutOrStdout(), SignFailed)
				return
			}

			err := signMetadata(configSign)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Encountered some issue: %v\n", err)
				fmt.Fprintln(cmd.OutOrStdout(), SignFailed)
				return
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Metadata file for role %s updated in dir: %s\n", configSign.role, configSign.metadataDir)
				fmt.Fprintln(cmd.OutOrStdout(), SignSucceeded)
			}
		},
	}
	cmdSign.Flags().StringVarP(&configSign.metadataDir, SignMetadataDir, "m", "", "Directory containing metadata files (required)")
	cmdSign.Flags().StringVarP(&configSign.role, SignRole, "r", "", "Signing role targets/snapshot/timestamp/root (required)")
	cmdSign.Flags().StringVarP(&configSign.privkeyFilepath, SignPrivkeyFilepath, "v", "", "Filepath of the private key for given role (required)")
	cmdSign.Flags().BoolVarP(&configSign.forced, SignForced, "f", false, "Forced sign with unrecognized key (optional)")
	cmdSign.MarkFlagRequired(SignMetadataDir)
	cmdSign.MarkFlagsRequiredTogether(SignMetadataDir, SignRole, SignPrivkeyFilepath)

	// Command to change signature threshold of different roles, except for root
	configChangeThreshold := configChangeThreshold{}
	cmdChangeThreshold := &cobra.Command{
		Use:   ChangeThresholdVerb,
		Short: "Change signature threshold by role, except root",
		Long:  fmt.Sprintf("Change signature threshold by role, except for root role (use change-root-key), supports `%s`/`%s`", ChangeThresholdActionAdd, ChangeThresholdActionReduce),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "Running change-threshold command...")
			fmt.Fprintf(cmd.OutOrStdout(), "Changing signature threshold of role: %s...\n", configSign.role)

			action := configChangeThreshold.action
			if action != ChangeThresholdActionAdd && action != ChangeThresholdActionReduce {
				fmt.Fprintf(cmd.OutOrStdout(), "Tips: only \"%s\" or \"%s\" is accepted for action", ChangeThresholdActionAdd, ChangeThresholdActionReduce)
				fmt.Fprintln(cmd.OutOrStdout(), ChangeThresholdFailed)
				return
			} else if configChangeThreshold.role == Root {
				fmt.Fprintf(cmd.OutOrStdout(), "Please use change-root-key command")
				fmt.Fprintln(cmd.OutOrStdout(), ChangeThresholdFailed)
				return
			}

			err := changeThreshold(configChangeThreshold)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Encountered some issue: %v\n", err)
				fmt.Fprintln(cmd.OutOrStdout(), ChangeThresholdFailed)
				return
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), ChangeThresholdSucceeded)
			}
		},
	}
	cmdChangeThreshold.Flags().StringVarP(&configChangeThreshold.metadataDir, ChangeThresholdMetadataDir, "m", "", "Directory containing metadata files (required)")
	cmdChangeThreshold.Flags().StringVarP(&configChangeThreshold.action, ChangeThresholdAction, "a", "", fmt.Sprintf("Threshold action: \"%s\" or \"%s\" (required)", ChangeThresholdActionAdd, ChangeThresholdActionReduce))
	cmdChangeThreshold.Flags().StringVarP(&configChangeThreshold.role, ChangeThresholdRole, "r", "", "Role to change threshold targets/snapshot/timestamp (required)")
	cmdChangeThreshold.Flags().StringVarP(&configChangeThreshold.rootPrivkeyFilepath, ChangeThresholdRootPrivkeyFilepath, "v", "", "Filepath of the root private key (required, at least 1)")
	cmdChangeThreshold.Flags().StringVarP(&configChangeThreshold.rolePrivkeyFilepath, ChangeThresholdRolePrivkeyFilepath, "i", "", "Filepath of the key for given role to be added(private)/removed(private or public) (required)")
	cmdChangeThreshold.MarkFlagRequired(ChangeThresholdMetadataDir)
	cmdChangeThreshold.MarkFlagsRequiredTogether(ChangeThresholdMetadataDir, ChangeThresholdAction, ChangeThresholdRole,
		ChangeThresholdRootPrivkeyFilepath, ChangeThresholdRolePrivkeyFilepath)

	// Command to update metadata files when new targets are added
	configVerify := configVerify{}
	cmdVerify := &cobra.Command{
		Use:   VerifyVerb,
		Short: "Verify repository metadata files and targets",
		Long:  "Verify repository metadata files and targets, output the current state of the repository",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", "Running verify command...")

			err := verifyMetadata(configVerify)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Encountered some issue: %v\n", err)
				fmt.Fprintln(cmd.OutOrStdout(), VerifyFailed)
				return
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), VerifySucceeded)
			}
		},
	}
	cmdVerify.Flags().StringVarP(&configVerify.repositoryDir, VerifyRepositoryDir, "d", "", "Directory containing target files (required)")
	cmdVerify.Flags().StringVarP(&configVerify.metadataDir, VerifyMetadataDir, "m", "", "Directory containing metadata files (required)")
	cmdVerify.MarkFlagRequired(VerifyRepositoryDir)
	cmdVerify.MarkFlagsRequiredTogether(VerifyRepositoryDir, VerifyMetadataDir)

	// Command to change root key
	// REMOVED replacement action
	configChangeRootKey := configChangeRootKey{}
	cmdChangeRootKey := &cobra.Command{
		Use:   ChangeRootKeyVerb,
		Short: "Change root key",
		Long:  fmt.Sprintf("Change root key, supports `%s`/`%s`", ChangeRootKeyActionAdd, ChangeRootKeyActionRemove),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Running change-root-key command...")

			// Check action
			action := configChangeRootKey.action
			if action != ChangeRootKeyActionAdd && action != ChangeRootKeyActionRemove {
				fmt.Fprintf(cmd.OutOrStdout(), "Tips: only \"%s\" or \"%s\" is accepted for action",
					ChangeRootKeyActionAdd, ChangeRootKeyActionRemove)
				fmt.Fprintln(cmd.OutOrStdout(), ChangeRootKeyFailed)
				return
			}

			cfg := &configChangeRootKey
			// Check replacing root key with same root key
			// if cfg.inputPrivkeyFilepath == cfg.replacementPrivkeyFilepath {
			// 	fmt.Fprintln(cmd.OutOrStdout(), "Replacement key and key to be replaced cannot be the same")
			// 	fmt.Fprintln(cmd.OutOrStdout(), ChangeRootKeyFailed)
			// 	return
			// }

			// Check input
			// if cfg.action == ChangeRootKeyActionReplace && cfg.replacementPrivkeyFilepath == "" {
			// 	fmt.Fprintln(cmd.OutOrStdout(), "Please provide replacement key for replace action")
			// 	fmt.Fprintln(cmd.OutOrStdout(), ChangeRootKeyFailed)
			// 	return
			// }

			if cfg.threshold < 1 {
				fmt.Fprintln(cmd.OutOrStdout(), "Threshold must be greater than 0")
				fmt.Fprintln(cmd.OutOrStdout(), ChangeRootKeyFailed)
				return
			}

			err := changeRootKey(configChangeRootKey)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Encountered some issue: %v\n", err)
				fmt.Fprintln(cmd.OutOrStdout(), ChangeRootKeyFailed)
				return
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), ChangeRootKeySucceeded)
			}

		},
	}
	cmdChangeRootKey.Flags().StringVarP(&configChangeRootKey.metadataDir, ChangeRootKeyMetadataDir, "m", "", "Directory containing metadata files (required)")
	cmdChangeRootKey.Flags().StringVarP(&configChangeRootKey.action, ChangeRootKeyAction, "a", "", fmt.Sprintf("Action: \"%s\" or \"%s\" (required)", ChangeRootKeyActionAdd, ChangeRootKeyActionRemove))
	cmdChangeRootKey.Flags().StringVarP(&configChangeRootKey.privkeyFilepath, ChangeRootKeyPrivkeyFilepath, "v", "", "Filepath of the root private key for signing (required)")
	cmdChangeRootKey.Flags().StringVarP(&configChangeRootKey.inputPrivkeyFilepath, ChangeRootKeyInputPrivkeyFilepath, "i", "", "Filepath of another root key to be added(private)/removed(public or private) (required)")
	// cmdChangeRootKey.Flags().StringVarP(&configChangeRootKey.replacementPrivkeyFilepath, ChangeRootKeyReplacementPrivkeyFilepath, "r", "", fmt.Sprintf("Filepath of another new root private key to be added as replacement (required for \"%s\")", ChangeRootKeyActionReplace))
	cmdChangeRootKey.Flags().Uint16VarP(&configChangeRootKey.expireIn, ChangeRootKeyExpire, "e", 365, "Metadata file expiration in days (required)")
	cmdChangeRootKey.Flags().Uint16VarP(&configChangeRootKey.threshold, ChangeRootKeyThreshold, "t", 1, "Root key threshold (required)")
	cmdChangeRootKey.MarkFlagRequired(ChangeRootKeyMetadataDir)
	cmdChangeRootKey.MarkFlagsRequiredTogether(ChangeRootKeyMetadataDir, ChangeRootKeyAction,
		ChangeRootKeyPrivkeyFilepath, ChangeRootKeyInputPrivkeyFilepath, ChangeRootKeyExpire, ChangeRootKeyThreshold)

	// Init cobra root command and add commands to it
	var rootCmd = &cobra.Command{Use: "App"}
	rootCmd.AddCommand(cmdKeygen)
	rootCmd.AddCommand(cmdInit)
	rootCmd.AddCommand(cmdUpdate)
	rootCmd.AddCommand(cmdSign)
	rootCmd.AddCommand(cmdChangeThreshold)
	rootCmd.AddCommand(cmdVerify)
	rootCmd.AddCommand(cmdChangeRootKey)

	// Generate documentation
	// err := doc.GenMarkdownTree(rootCmd, "../../test/output/")
	// if err != nil {
	// 	fmt.Printf("fail to generate markdown documentation: %v\n", err)
	// }

	return rootCmd
}
