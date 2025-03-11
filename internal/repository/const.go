package repository

const (
	DefaultExpireIn = 365

	// Roles
	Root      = "root"
	Targets   = "targets"
	Snapshot  = "snapshot"
	Timestamp = "timestamp"

	// Flags
	// KeygenVerb
	KeygenVerb            = "keygen"
	KeygenOutputDir       = "output-dir"
	KeygenPrivkeyFilename = "priv-filename"
	KeygenPubkeyFilename  = "pub-filename"
	// InitVerb
	InitVerb                     = "init"
	InitRepositoryDir            = "repository-dir"
	InitOutputDir                = "output-dir"
	InitRootPrivkeyFilepath      = "root-priv-filepath"
	InitTargetsPrivkeyFilepath   = "targets-priv-filepath"
	InitSnapshotPrivkeyFilepath  = "snapshot-priv-filepath"
	InitTimestampPrivkeyFilepath = "timestamp-priv-filepath"
	InitRootThreshold            = "root-threshold"
	InitTargetsThreshold         = "targets-threshold"
	InitSnapshotThreshold        = "snapshot-threshold"
	InitTimestampThreshold       = "timestamp-threshold"
	InitExpire                   = "expire"
	// UpdateVerb
	UpdateVerb                     = "update"
	UpdateRepositoryDir            = "repository-dir"
	UpdateMetadataDir              = "metadata-dir"
	UpdateTargetsPrivkeyFilepath   = "targets-priv-filepath"
	UpdateSnapshotPrivkeyFilepath  = "snapshot-priv-filepath"
	UpdateTimestampPrivkeyFilepath = "timestamp-priv-filepath"
	UpdateExpire                   = "expire"
	UpdateAskConfirmation          = "ask-confirmation"
	// SignVerb
	SignVerb            = "sign"
	SignMetadataDir     = "metadata-dir"
	SignRole            = "role"
	SignPrivkeyFilepath = "priv-filepath"
	SignForced          = "forced"
	// Change threshold
	ChangeThresholdVerb                = "change-threshold"
	ChangeThresholdMetadataDir         = "metadata-dir"
	ChangeThresholdAction              = "action"
	ChangeThresholdActionAdd           = "add"
	ChangeThresholdActionReduce        = "reduce"
	ChangeThresholdRole                = "role"
	ChangeThresholdRootPrivkeyFilepath = "root-priv-filepath"
	ChangeThresholdRolePrivkeyFilepath = "role-priv-filepath"
	// Verify
	VerifyVerb          = "verify"
	VerifyRepositoryDir = "repository-dir"
	VerifyMetadataDir   = "metadata-dir"
	// Change root key
	ChangeRootKeyVerb                       = "change-root-key"
	ChangeRootKeyMetadataDir                = "metadata-dir"
	ChangeRootKeyAction                     = "action"
	ChangeRootKeyActionAdd                  = "add"
	ChangeRootKeyActionRemove               = "remove"
	ChangeRootKeyActionReplace              = "replace"
	ChangeRootKeyPrivkeyFilepath            = "priv-filepath"
	ChangeRootKeyInputPrivkeyFilepath       = "input-priv-filepath"
	ChangeRootKeyReplacementPrivkeyFilepath = "repl-priv-filepath"
	ChangeRootKeyExpire                     = "expire"
	ChangeRootKeyThreshold                  = "threshold"

	// Operation result messages
	KeygenFailed             = "----------KEYGEN FAILED----------"
	KeygenSucceeded          = "----------KEYGEN SUCCEEDED----------"
	InitFailed               = "----------INIT FAILED----------"
	InitSucceeded            = "----------INIT SUCCEEDED----------"
	UpdateFailed             = "----------UPDATE FAILED----------"
	UpdateSucceeded          = "----------UPDATE SUCCEEDED----------"
	SignFailed               = "----------SIGN FAILED----------"
	SignSucceeded            = "----------SIGN SUCCEEDED----------"
	ChangeThresholdFailed    = "----------CHANGE THRESHOLD FAILED----------"
	ChangeThresholdSucceeded = "----------CHANGE THRESHOLD SUCCEEDED----------"
	VerifyFailed             = "----------VERIFY FAILED----------"
	VerifySucceeded          = "----------VERIFY SUCCEEDED----------"
	ChangeRootKeyFailed      = "----------CHANGE ROOT KEY FAILED----------"
	ChangeRootKeySucceeded   = "----------CHANGE ROOT KEY SUCCEEDED----------"

	// Testing constants, paths are relative to the resository_test.go file
	TestDir                         = "../../test/"
	TestRepoDir                     = "../../test/repo/"
	TestRepoMetadataDir             = "../../test/repo-metadata/"
	TestOutputDir                   = "../../test/output/"
	TestOutputMetadataDir           = "../../test/output/metadata/"
	TestRootPrivKeyFilepath         = "../../test/keys/rootPrivateKey"
	TestRootPrivKeyTwoFilepath      = "../../test/keys/rootPrivateKeyTwo"
	TestTargetsPrivKeyFilepath      = "../../test/keys/targetsPrivateKey"
	TestTargetsPrivKeyTwoFilepath   = "../../test/keys/targetsPrivateKeyTwo"
	TestSnapshotPrivKeyFilepath     = "../../test/keys/snapshotPrivateKey"
	TestSnapshotPrivKeyTwoFilepath  = "../../test/keys/snapshotPrivateKeyTwo"
	TestTimestampPrivKeyFilepath    = "../../test/keys/timestampPrivateKey"
	TestTimestampPrivKeyTwoFilepath = "../../test/keys/timestampPrivateKeyTwo"

	TestRootPubKeyFilepath         = "../../test/keys/rootPublicKey"
	TestRootPubKeyTwoFilepath      = "../../test/keys/rootPublicKeyTwo"
	TestTargetsPubKeyFilepath      = "../../test/keys/targetsPublicKey"
	TestTargetsPubKeyTwoFilepath   = "../../test/keys/targetsPublicKeyTwo"
	TestSnapshotPubKeyFilepath     = "../../test/keys/snapshotPublicKey"
	TestSnapshotPubKeyTwoFilepath  = "../../test/keys/snapshotPublicKeyTwo"
	TestTimestampPubKeyFilepath    = "../../test/keys/timestampPublicKey"
	TestTimestampPubKeyTwoFilepath = "../../test/keys/timestampPublicKeyTwo"
)

func getRoles() []string {
	return []string{
		Root, Targets, Snapshot, Timestamp,
	}
}
