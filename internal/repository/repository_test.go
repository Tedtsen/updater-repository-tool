package repository

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"see_updater/internal/pkg/cryptography"
	"see_updater/internal/pkg/datetime"
	"see_updater/internal/pkg/filesystem"
	"see_updater/internal/pkg/metahelper"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

// Keygen tests
func TestKeygenShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		privkeyFilename string
		pubkeyFilename  string
		outputDir       string
		caseDescription string // optional, just for the sake of clarification
	}{
		{"testPrivKey", "testPubKey", fmt.Sprint(TestDir + "/outputt"), "non-existent directory"},
		{"testPrivKey", "testPrivKey", fmt.Sprint(TestOutputDir), "same private and public key name"},
		{"testPrivKey", "testPubKey", fmt.Sprint(TestOutputDir + "/non-existent-child-dir"), "non-existent child directory"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			KeygenVerb,
			fmt.Sprintf("--%s=%s", KeygenPrivkeyFilename, c.privkeyFilename),
			fmt.Sprintf("--%s=%s", KeygenPubkeyFilename, c.pubkeyFilename),
			fmt.Sprintf("--%s=%s", KeygenOutputDir, c.outputDir),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] == KeygenSucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
	}

	// Clear outputs
	os.RemoveAll(TestOutputDir)
	os.Mkdir(TestOutputDir, 0700) // user can write
	// TODO Test if filename already existed
}
func TestKeygenShouldPass(t *testing.T) {
	casesShouldPass := []struct {
		privkeyFilename string
		pubkeyFilename  string
		outputDir       string
		caseDescription string // optional, just for the sake of clarification
	}{
		{"testPrivKey", "testPubKey", fmt.Sprint(TestOutputDir), "expected input"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldPass {
		out.Reset()
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			KeygenVerb,
			fmt.Sprintf("--%s=%s", KeygenPrivkeyFilename, c.privkeyFilename),
			fmt.Sprintf("--%s=%s", KeygenPubkeyFilename, c.pubkeyFilename),
			fmt.Sprintf("--%s=%s", KeygenOutputDir, c.outputDir),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] != KeygenSucceeded {
			t.Fatal(lines)
		}

		bytes, err := filesystem.ReadBytesFromFile(TestOutputDir + "/" + c.privkeyFilename)
		if err != nil {
			t.Fatal(lines, err)
		}
		_, err = cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
		if err != nil {
			t.Fatal(lines, err)
		}
		bytes, err = filesystem.ReadBytesFromFile(TestOutputDir + "/" + c.pubkeyFilename)
		if err != nil {
			t.Fatal(lines, err)
		}
		_, err = cryptography.ParseRsaPublicKeyFromPemStr(string(bytes))
		if err != nil {
			t.Fatal(lines, err)
		}
		fmt.Println(lines)
	}
	// Clear outputs
	os.RemoveAll(TestOutputDir)
	os.Mkdir(TestOutputDir, 0700) // user can write
}

// Init tests
func TestInitThresholdShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		repositoryDir            string
		outputDir                string
		rootPrivkeyFilepath      string
		targetsPrivkeyFilepath   string
		snapshotPrivkeyFilepath  string
		timestampPrivkeyFilepath string
		rootThreshold            string
		targetsThreshold         string
		snapshotThreshold        string
		timestampThreshold       string
		expire                   string
		caseDescription          string
	}{
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, TestTimestampPrivKeyFilepath,
			"2", "1", "1", "1", "365", "threshold and no. key mismatch"},
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath + ";" + TestRootPrivKeyTwoFilepath,
			TestTargetsPrivKeyFilepath + ";" + TestTargetsPrivKeyTwoFilepath,
			TestSnapshotPrivKeyFilepath + ";" + TestSnapshotPrivKeyTwoFilepath,
			TestTimestampPrivKeyFilepath + ";" + TestTimestampPrivKeyTwoFilepath,
			"2", "1", "1", "1", "365", "threshold and no. key mismatch"},
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath + ";" + TestRootPrivKeyTwoFilepath,
			TestTargetsPrivKeyFilepath + ";" + TestTargetsPrivKeyTwoFilepath,
			TestSnapshotPrivKeyFilepath + ";" + TestSnapshotPrivKeyTwoFilepath,
			TestTimestampPrivKeyFilepath + ";" + TestTimestampPrivKeyTwoFilepath,
			"1", "1", "2", "1", "365", "threshold and no. key mismatch"},
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath + ";" + TestRootPrivKeyTwoFilepath,
			TestTargetsPrivKeyFilepath + ";" + TestTargetsPrivKeyTwoFilepath,
			TestSnapshotPrivKeyFilepath + ";" + TestSnapshotPrivKeyTwoFilepath,
			TestTimestampPrivKeyFilepath + ";" + TestTimestampPrivKeyTwoFilepath,
			"1", "1", "1", "2", "365", "threshold and no. key mismatch"},
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, "",
			"1", "1", "1", "1", "365", "key not provided"},
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, TestTimestampPrivKeyFilepath,
			"1", "1", "1", "0", "365", "threshold is 0"},
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, "",
			"1", "1", "1", "0", "365", "threshold is 0"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			InitVerb,
			fmt.Sprintf("--%s=%s", InitRepositoryDir, c.repositoryDir),
			fmt.Sprintf("--%s=%s", InitOutputDir, c.outputDir),
			fmt.Sprintf("--%s=%s", InitRootPrivkeyFilepath, c.rootPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitTargetsPrivkeyFilepath, c.targetsPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitSnapshotPrivkeyFilepath, c.snapshotPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitTimestampPrivkeyFilepath, c.timestampPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitRootThreshold, c.rootThreshold),
			fmt.Sprintf("--%s=%s", InitTargetsThreshold, c.targetsThreshold),
			fmt.Sprintf("--%s=%s", InitSnapshotThreshold, c.snapshotThreshold),
			fmt.Sprintf("--%s=%s", InitTimestampThreshold, c.timestampThreshold),
			fmt.Sprintf("--%s=%s", InitExpire, c.expire),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] == InitSucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
	}
	// Clear outputs
	os.RemoveAll(TestOutputDir)
	os.Mkdir(TestOutputDir, 0700) // user can write
}
func TestInitKeyFilesShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		repositoryDir            string
		outputDir                string
		rootPrivkeyFilepath      string
		targetsPrivkeyFilepath   string
		snapshotPrivkeyFilepath  string
		timestampPrivkeyFilepath string
		rootThreshold            string
		targetsThreshold         string
		snapshotThreshold        string
		timestampThreshold       string
		expire                   string
		caseDescription          string
	}{
		{TestRepoDir, TestOutputMetadataDir, TestRootPubKeyFilepath, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, TestTimestampPrivKeyFilepath,
			"1", "1", "1", "1", "365", "public key input"},
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath, TestTargetsPubKeyFilepath, TestSnapshotPrivKeyFilepath, TestTimestampPrivKeyFilepath,
			"1", "1", "1", "1", "365", "public key input"},
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, TestSnapshotPubKeyFilepath, TestTimestampPrivKeyFilepath,
			"1", "1", "1", "1", "365", "public key input"},
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, TestTimestampPubKeyFilepath,
			"1", "1", "1", "1", "365", "public key input"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			InitVerb,
			fmt.Sprintf("--%s=%s", InitRepositoryDir, c.repositoryDir),
			fmt.Sprintf("--%s=%s", InitOutputDir, c.outputDir),
			fmt.Sprintf("--%s=%s", InitRootPrivkeyFilepath, c.rootPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitTargetsPrivkeyFilepath, c.targetsPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitSnapshotPrivkeyFilepath, c.snapshotPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitTimestampPrivkeyFilepath, c.timestampPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitRootThreshold, c.rootThreshold),
			fmt.Sprintf("--%s=%s", InitTargetsThreshold, c.targetsThreshold),
			fmt.Sprintf("--%s=%s", InitSnapshotThreshold, c.snapshotThreshold),
			fmt.Sprintf("--%s=%s", InitTimestampThreshold, c.timestampThreshold),
			fmt.Sprintf("--%s=%s", InitExpire, c.expire),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] == InitSucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
	}
	// Clear outputs
	os.RemoveAll(TestOutputDir)
	os.Mkdir(TestOutputDir, 0700) // user can write
}
func TestInitShouldPass(t *testing.T) {
	casesShouldPass := []struct {
		repositoryDir            string
		outputDir                string
		rootPrivkeyFilepath      string
		targetsPrivkeyFilepath   string
		snapshotPrivkeyFilepath  string
		timestampPrivkeyFilepath string
		rootThreshold            string
		targetsThreshold         string
		snapshotThreshold        string
		timestampThreshold       string
		expire                   string
		caseDescription          string
	}{
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, TestTimestampPrivKeyFilepath,
			"1", "1", "1", "1", "365", "expected input"},
		{TestRepoDir, TestOutputMetadataDir, TestRootPrivKeyFilepath + ";" + TestRootPrivKeyTwoFilepath,
			TestTargetsPrivKeyFilepath + ";" + TestTargetsPrivKeyTwoFilepath,
			TestSnapshotPrivKeyFilepath + ";" + TestSnapshotPrivKeyTwoFilepath,
			TestTimestampPrivKeyFilepath + ";" + TestTimestampPrivKeyTwoFilepath,
			"2", "2", "2", "2", "365", "expected input with double keys"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldPass {
		out.Reset()
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			InitVerb,
			fmt.Sprintf("--%s=%s", InitRepositoryDir, c.repositoryDir),
			fmt.Sprintf("--%s=%s", InitOutputDir, c.outputDir),
			fmt.Sprintf("--%s=%s", InitRootPrivkeyFilepath, c.rootPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitTargetsPrivkeyFilepath, c.targetsPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitSnapshotPrivkeyFilepath, c.snapshotPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitTimestampPrivkeyFilepath, c.timestampPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", InitRootThreshold, c.rootThreshold),
			fmt.Sprintf("--%s=%s", InitTargetsThreshold, c.targetsThreshold),
			fmt.Sprintf("--%s=%s", InitSnapshotThreshold, c.snapshotThreshold),
			fmt.Sprintf("--%s=%s", InitTimestampThreshold, c.timestampThreshold),
			fmt.Sprintf("--%s=%s", InitExpire, c.expire),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] != InitSucceeded {
			t.Fatal(lines)
		}
		// Verify
		absPath, _ := filepath.Abs(TestOutputMetadataDir)
		err := verifyAllRolesTestHelper(absPath)
		if err != nil {
			t.Fatal(lines, err)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
	// TODO Test if all files in respository directory are included in Targets file (with verification of hashes and lengths)
}

// Update tests
func TestUpdateThresholdShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		respositoryDir           string
		metadataDir              string
		targetsPrivkeyFilepath   string
		snapshotPrivkeyFilepath  string
		timestampPrivkeyFilepath string
		expire                   string
		askConfirmation          string
		caseDescription          string
	}{
		{TestRepoDir, TestOutputMetadataDir, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, TestTimestampPrivKeyFilepath,
			"365", "FALSE", "second update not enough signature (threshold not reached)"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 2
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: c.respositoryDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath},
				Targets:   {TestTargetsPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath},
				Snapshot:  {TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath},
				Timestamp: {TestTimestampPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath},
			},
			rootThreshhold:     2,
			targetsThreshold:   2,
			snapshotThreshold:  2,
			timestampThreshold: 2,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. First time update with 1 key for each role (every role's threshold = 2)
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			UpdateVerb,
			fmt.Sprintf("--%s=%s", UpdateRepositoryDir, c.respositoryDir),
			fmt.Sprintf("--%s=%s", UpdateMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", UpdateTargetsPrivkeyFilepath, c.targetsPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateSnapshotPrivkeyFilepath, c.snapshotPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateTimestampPrivkeyFilepath, c.timestampPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateExpire, c.expire),
			fmt.Sprintf("--%s=%s", UpdateAskConfirmation, c.askConfirmation),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		// First time update should pass
		if lines[len(lines)-1] != UpdateSucceeded {
			t.Fatal(lines)
		}
		// 3. Second time update should fail, previous version's thresholds not reached
		cmd = NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			UpdateVerb,
			fmt.Sprintf("--%s=%s", UpdateRepositoryDir, c.respositoryDir),
			fmt.Sprintf("--%s=%s", UpdateMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", UpdateTargetsPrivkeyFilepath, c.targetsPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateSnapshotPrivkeyFilepath, c.snapshotPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateTimestampPrivkeyFilepath, c.timestampPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateExpire, c.expire),
			fmt.Sprintf("--%s=%s", UpdateAskConfirmation, c.askConfirmation),
		})
		cmd.Execute()
		lines = convBufferToStrings(out)
		// Second time update should fail
		if lines[len(lines)-1] == UpdateSucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestUpdateKeyFilesShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		respositoryDir           string
		metadataDir              string
		targetsPrivkeyFilepath   string
		snapshotPrivkeyFilepath  string
		timestampPrivkeyFilepath string
		expire                   string
		askConfirmation          string
		caseDescription          string
	}{
		{TestRepoDir, TestOutputMetadataDir, TestTargetsPubKeyFilepath, TestSnapshotPrivKeyFilepath, TestTimestampPrivKeyFilepath,
			"365", "FALSE", "public key as input"},
		{TestRepoDir, TestOutputMetadataDir, TestTargetsPrivKeyFilepath, TestSnapshotPubKeyFilepath, TestTimestampPrivKeyFilepath,
			"365", "FALSE", "public key as input"},
		{TestRepoDir, TestOutputMetadataDir, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, TestTimestampPubKeyFilepath,
			"365", "FALSE", "public key as input"},
		{TestRepoDir, TestOutputMetadataDir, TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyFilepath,
			"365", "FALSE", "wrong private key"},
		{TestRepoDir, TestOutputMetadataDir, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyFilepath,
			"365", "FALSE", "wrong private key"},
		{TestRepoDir, TestOutputMetadataDir, TestTargetsPrivKeyFilepath, TestTimestampPrivKeyFilepath, TestTimestampPrivKeyFilepath,
			"365", "FALSE", "wrong private key"},
		{TestRepoDir, TestOutputMetadataDir, "", TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyFilepath,
			"365", "FALSE", "insufficient key"},
		{TestRepoDir, TestOutputMetadataDir, TestTargetsPrivKeyFilepath, "", TestSnapshotPrivKeyFilepath,
			"365", "FALSE", "insufficient key"},
		{TestRepoDir, TestOutputMetadataDir, "", "", TestTimestampPrivKeyFilepath,
			"365", "FALSE", "insufficient key"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 2
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: c.respositoryDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath},
				Targets:   {TestTargetsPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath},
				Snapshot:  {TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath},
				Timestamp: {TestTimestampPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath},
			},
			rootThreshhold:     2,
			targetsThreshold:   2,
			snapshotThreshold:  2,
			timestampThreshold: 2,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. First time update with 1 key for each role (every role's threshold = 2)
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			UpdateVerb,
			fmt.Sprintf("--%s=%s", UpdateRepositoryDir, c.respositoryDir),
			fmt.Sprintf("--%s=%s", UpdateMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", UpdateTargetsPrivkeyFilepath, c.targetsPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateSnapshotPrivkeyFilepath, c.snapshotPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateTimestampPrivkeyFilepath, c.timestampPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateExpire, c.expire),
			fmt.Sprintf("--%s=%s", UpdateAskConfirmation, c.askConfirmation),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] == UpdateSucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestUpdateShouldPass(t *testing.T) {
	casesShouldPass := []struct {
		respositoryDir           string
		metadataDir              string
		targetsPrivkeyFilepath   string
		snapshotPrivkeyFilepath  string
		timestampPrivkeyFilepath string
		expire                   string
		askConfirmation          string
		caseDescription          string
	}{
		{TestRepoDir, TestOutputMetadataDir, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, TestTimestampPrivKeyFilepath,
			"365", "FALSE", "expected input"},
		{TestRepoDir, TestOutputMetadataDir, TestTargetsPrivKeyFilepath, "", "",
			"365", "FALSE", "expected input"},
		{TestRepoDir, TestOutputMetadataDir, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, "",
			"365", "FALSE", "expected input"},
	}
	out := new(bytes.Buffer)
	for _, c := range casesShouldPass {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 2
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: c.respositoryDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath},
				Targets:   {TestTargetsPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath},
				Snapshot:  {TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath},
				Timestamp: {TestTimestampPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath},
			},
			rootThreshhold:     2,
			targetsThreshold:   2,
			snapshotThreshold:  2,
			timestampThreshold: 2,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. First time update with 1 key for each role (every role's threshold = 2)
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			UpdateVerb,
			fmt.Sprintf("--%s=%s", UpdateRepositoryDir, c.respositoryDir),
			fmt.Sprintf("--%s=%s", UpdateMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", UpdateTargetsPrivkeyFilepath, c.targetsPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateSnapshotPrivkeyFilepath, c.snapshotPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateTimestampPrivkeyFilepath, c.timestampPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", UpdateExpire, c.expire),
			fmt.Sprintf("--%s=%s", UpdateAskConfirmation, c.askConfirmation),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		// First time update should pass
		if lines[len(lines)-1] != UpdateSucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}

// Sign tests
func TestSignKeyFilesShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		metadataDir     string
		role            string
		privkeyFilepath string
		caseDescription string
	}{

		{TestOutputMetadataDir, Targets, TestTargetsPubKeyFilepath, "public key input"},
		{TestOutputMetadataDir, Snapshot, TestSnapshotPubKeyFilepath, "public key input"},
		{TestOutputMetadataDir, Timestamp, TestTimestampPubKeyFilepath, "public key input"},
		{TestOutputMetadataDir, Targets, TestTargetsPrivKeyFilepath, "duplicate signature"},
		{TestOutputMetadataDir, Snapshot, TestSnapshotPrivKeyFilepath, "duplicate signature"},
		{TestOutputMetadataDir, Timestamp, TestTimestampPrivKeyFilepath, "duplicate signature"},
		{TestOutputMetadataDir, Targets, TestTargetsPrivKeyTwoFilepath, "invalid key"},
		{TestOutputMetadataDir, Snapshot, TestSnapshotPrivKeyTwoFilepath, "invalid key"},
		{TestOutputMetadataDir, Timestamp, TestTimestampPrivKeyTwoFilepath, "invalid key"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 2
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath /*, TestRootPrivKeyTwoFilepath*/},
				Targets:   {TestTargetsPrivKeyFilepath /*, TestTargetsPrivKeyTwoFilepath*/},
				Snapshot:  {TestSnapshotPrivKeyFilepath /*, TestSnapshotPrivKeyTwoFilepath*/},
				Timestamp: {TestTimestampPrivKeyFilepath /*, TestTimestampPrivKeyTwoFilepath*/},
			},
			rootThreshhold:     1,
			targetsThreshold:   1,
			snapshotThreshold:  1,
			timestampThreshold: 1,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. Sign
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			SignVerb,
			fmt.Sprintf("--%s=%s", SignMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", SignRole, c.role),
			fmt.Sprintf("--%s=%s", SignPrivkeyFilepath, c.privkeyFilepath),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] == SignSucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestSignShouldPass(t *testing.T) {
	casesShouldPass := []struct {
		metadataDir     string
		role            string
		privkeyFilepath string
		caseDescription string
	}{
		{TestOutputMetadataDir, Targets, TestTargetsPrivKeyTwoFilepath, "expected input"},
		{TestOutputMetadataDir, Snapshot, TestSnapshotPrivKeyTwoFilepath, "expected input"},
		{TestOutputMetadataDir, Timestamp, TestTimestampPrivKeyTwoFilepath, "expected input"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldPass {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 2
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath},
				Targets:   {TestTargetsPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath},
				Snapshot:  {TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath},
				Timestamp: {TestTimestampPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath},
			},
			rootThreshhold:     2,
			targetsThreshold:   2,
			snapshotThreshold:  2,
			timestampThreshold: 2,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. Update with 1 key for every role (threshold = 1/2)
		err = updateRepoMetadataTestHelper(configUpdate{
			repositoryDir:            TestRepoDir,
			metadataDir:              c.metadataDir,
			targetsPrivkeyFilepath:   TestTargetsPrivKeyFilepath,
			snapshotPrivkeyFilepath:  TestSnapshotPrivKeyFilepath,
			timestampPrivkeyFilepath: TestTimestampPrivKeyFilepath,
			expireIn:                 365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 3. Sign (threshold = 2/2)
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			SignVerb,
			fmt.Sprintf("--%s=%s", SignMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", SignRole, c.role),
			fmt.Sprintf("--%s=%s", SignPrivkeyFilepath, c.privkeyFilepath),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] != SignSucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestSignMultiRoundsShouldPass(t *testing.T) {
	casesShouldPass := []struct {
		metadataDir     string
		role            string
		privkeyFilepath string
		caseDescription string
	}{
		{TestOutputMetadataDir, Targets, TestTargetsPrivKeyTwoFilepath, "expected input"},
		{TestOutputMetadataDir, Snapshot, TestSnapshotPrivKeyTwoFilepath, "expected input"},
		{TestOutputMetadataDir, Timestamp, TestTimestampPrivKeyTwoFilepath, "expected input"},
	}

	// 1. Init a new repo with every role's threshold = 2
	err := initRepoMetadataTestHelper(configInit{
		repositoryDir: TestRepoDir,
		outputDir:     TestOutputMetadataDir,
		rolesPrivkeyFilepaths: map[string][]string{
			Root:      {TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath},
			Targets:   {TestTargetsPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath},
			Snapshot:  {TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath},
			Timestamp: {TestTimestampPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath},
		},
		rootThreshhold:     2,
		targetsThreshold:   2,
		snapshotThreshold:  2,
		timestampThreshold: 2,
		expireIn:           365,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 2. Update with 1 key for every role (threshold = 1/2)
	err = updateRepoMetadataTestHelper(configUpdate{
		repositoryDir:            TestRepoDir,
		metadataDir:              TestOutputMetadataDir,
		targetsPrivkeyFilepath:   TestTargetsPrivKeyFilepath,
		snapshotPrivkeyFilepath:  TestSnapshotPrivKeyFilepath,
		timestampPrivkeyFilepath: TestTimestampPrivKeyFilepath,
		expireIn:                 365,
	})
	if err != nil {
		t.Fatal(err)
	}

	out := new(bytes.Buffer)
	lines := convBufferToStrings(out)
	for _, c := range casesShouldPass {
		out.Reset()
		// 3. Sign (1 round for every role, 3 rounds in total)
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			SignVerb,
			fmt.Sprintf("--%s=%s", SignMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", SignRole, c.role),
			fmt.Sprintf("--%s=%s", SignPrivkeyFilepath, c.privkeyFilepath),
		})
		cmd.Execute()
		lines = convBufferToStrings(out)
		if lines[len(lines)-1] != SignSucceeded {
			t.Fatal(lines)
		}
	}

	// 4. Verify
	err = verifyAllRolesTestHelper(TestOutputMetadataDir)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(lines)
	// Clear outputs
	os.RemoveAll(TestOutputDir)
	os.Mkdir(TestOutputDir, 0700) // user can write
}

// Init repo with thresholds = 1 to test change threshold
func TestChangeThresholdSingleKeyShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		metadataDir         string
		action              string
		role                string
		rootPrivkeyFilepath string
		rolePrivkeyFilepath string
		caseDescription     string
	}{
		// Reminder: Reduce by role public key is allowed!
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Root, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, "changing root threshold"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Targets, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, "zero threshold"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Snapshot, TestRootPrivKeyFilepath, TestSnapshotPrivKeyFilepath, "zero threshold"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Timestamp, TestRootPrivKeyFilepath, TestTimestampPrivKeyFilepath, "zero threshold"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Targets, TestRootPrivKeyTwoFilepath, TestTargetsPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Snapshot, TestRootPrivKeyTwoFilepath, TestSnapshotPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Timestamp, TestRootPrivKeyTwoFilepath, TestTimestampPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Targets, TestRootPubKeyFilepath, TestTargetsPrivKeyFilepath, "root public key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Root, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, "changing root threshold"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Targets, TestRootPrivKeyTwoFilepath, TestTargetsPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Snapshot, TestRootPrivKeyTwoFilepath, TestSnapshotPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Timestamp, TestRootPrivKeyTwoFilepath, TestTimestampPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Targets, TestRootPubKeyFilepath, TestTargetsPrivKeyFilepath, "root public key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Targets, TestRootPrivKeyFilepath, TestTargetsPubKeyFilepath, "role public key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Targets, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, "duplicate key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Snapshot, TestRootPrivKeyFilepath, TestSnapshotPrivKeyFilepath, "duplicate key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Timestamp, TestRootPrivKeyFilepath, TestTimestampPrivKeyFilepath, "duplicate key"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 1
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath /*, TestRootPrivKeyTwoFilepath*/},
				Targets:   {TestTargetsPrivKeyFilepath /*, TestTargetsPrivKeyTwoFilepath*/},
				Snapshot:  {TestSnapshotPrivKeyFilepath /*, TestSnapshotPrivKeyTwoFilepath*/},
				Timestamp: {TestTimestampPrivKeyFilepath /*, TestTimestampPrivKeyTwoFilepath*/},
			},
			rootThreshhold:     1,
			targetsThreshold:   1,
			snapshotThreshold:  1,
			timestampThreshold: 1,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. Change threshold
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			ChangeThresholdVerb,
			fmt.Sprintf("--%s=%s", ChangeThresholdMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", ChangeThresholdAction, c.action),
			fmt.Sprintf("--%s=%s", ChangeThresholdRole, c.role),
			fmt.Sprintf("--%s=%s", ChangeThresholdRootPrivkeyFilepath, c.rootPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", ChangeThresholdRolePrivkeyFilepath, c.rolePrivkeyFilepath),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] == ChangeThresholdSucceeded {
			t.Fatal(lines)
		}
		// 3. Verify integrity
		err = verifyAllRolesTestHelper(c.metadataDir)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}

// Init repo with thresholds = 2 to test change threshold
func TestChangeThresholdDoubleKeyShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		metadataDir         string
		action              string
		role                string
		rootPrivkeyFilepath string
		rolePrivkeyFilepath string
		caseDescription     string
	}{
		// Reminder: Reduce by role public key is allowed!
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Root, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, "changing root threshold"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Targets, TestTargetsPrivKeyFilepath, TestTargetsPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Snapshot, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Timestamp, TestTargetsPrivKeyFilepath, TestTimestampPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Targets, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, "wrong role private key"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Snapshot, TestTargetsPrivKeyFilepath, TestTargetsPrivKeyFilepath, "wrong role private key"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Timestamp, TestTargetsPrivKeyFilepath, TestTargetsPrivKeyFilepath, "wrong role private key"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Targets, TestRootPubKeyFilepath, TestTargetsPrivKeyFilepath, "root public key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Root, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, "changing root threshold"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Targets, TestTargetsPrivKeyFilepath, TestTargetsPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Snapshot, TestTargetsPrivKeyFilepath, TestSnapshotPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Timestamp, TestTargetsPrivKeyFilepath, TestTimestampPrivKeyFilepath, "wrong root private key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Targets, TestRootPubKeyFilepath, TestTargetsPrivKeyFilepath, "public key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Targets, TestRootPrivKeyFilepath, TestTargetsPubKeyFilepath, "public key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Targets, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, "duplicate key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Snapshot, TestRootPrivKeyFilepath, TestSnapshotPrivKeyFilepath, "duplicate key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Timestamp, TestRootPrivKeyFilepath, TestTimestampPrivKeyFilepath, "duplicate key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Targets, TestRootPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath, "duplicate key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Snapshot, TestRootPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath, "duplicate key"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Timestamp, TestRootPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath, "duplicate key"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 2
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath},
				Targets:   {TestTargetsPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath},
				Snapshot:  {TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath},
				Timestamp: {TestTimestampPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath},
			},
			rootThreshhold:     2,
			targetsThreshold:   2,
			snapshotThreshold:  2,
			timestampThreshold: 2,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. Change threshold
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			ChangeThresholdVerb,
			fmt.Sprintf("--%s=%s", ChangeThresholdMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", ChangeThresholdAction, c.action),
			fmt.Sprintf("--%s=%s", ChangeThresholdRole, c.role),
			fmt.Sprintf("--%s=%s", ChangeThresholdRootPrivkeyFilepath, c.rootPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", ChangeThresholdRolePrivkeyFilepath, c.rolePrivkeyFilepath),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] == ChangeThresholdSucceeded {
			t.Fatal(lines)
		}
		// 3. Verify integrity (should fail, root metadata not enough signatures(1/2))
		err = verifyAllRolesTestHelper(c.metadataDir)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestChangeThresholdSingleKeyShouldPass(t *testing.T) {
	casesShouldPass := []struct {
		metadataDir         string
		action              string
		role                string
		rootPrivkeyFilepath string
		rolePrivkeyFilepath string
		caseDescription     string
	}{
		// Reminder: Reduce by role public key is allowed
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Targets, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, "expected add input"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Snapshot, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, "expected add input"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Timestamp, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, "expected add input"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldPass {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 1
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath /*, TestRootPrivKeyTwoFilepath*/},
				Targets:   {TestTargetsPrivKeyFilepath /*, TestTargetsPrivKeyTwoFilepath*/},
				Snapshot:  {TestSnapshotPrivKeyFilepath /*, TestSnapshotPrivKeyTwoFilepath*/},
				Timestamp: {TestTimestampPrivKeyFilepath /*, TestTimestampPrivKeyTwoFilepath*/},
			},
			rootThreshhold:     1,
			targetsThreshold:   1,
			snapshotThreshold:  1,
			timestampThreshold: 1,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. Change threshold
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			ChangeThresholdVerb,
			fmt.Sprintf("--%s=%s", ChangeThresholdMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", ChangeThresholdAction, c.action),
			fmt.Sprintf("--%s=%s", ChangeThresholdRole, c.role),
			fmt.Sprintf("--%s=%s", ChangeThresholdRootPrivkeyFilepath, c.rootPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", ChangeThresholdRolePrivkeyFilepath, c.rolePrivkeyFilepath),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] != ChangeThresholdSucceeded {
			t.Fatal(lines)
		}
		// Verification should fail, successful sign will output a new root metadata file,
		// however with only 1 root signature (1/2 threshold)
		err = verifyAllRolesTestHelper(c.metadataDir)
		if err == nil {
			t.Fatal(err)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestChangeThresholdDoubleKeyShouldPass(t *testing.T) {
	casesShouldPass := []struct {
		metadataDir         string
		action              string
		role                string
		rootPrivkeyFilepath string
		rolePrivkeyFilepath string
		caseDescription     string
	}{
		// Reminder: Reduce by role public key is allowed
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Targets, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, "expected reduce input"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Snapshot, TestRootPrivKeyFilepath, TestSnapshotPrivKeyFilepath, "expected reduce input"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Timestamp, TestRootPrivKeyFilepath, TestTimestampPrivKeyFilepath, "expected reduce input"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Targets, TestRootPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath, "expected reduce input"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Snapshot, TestRootPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath, "expected reduce input"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Timestamp, TestRootPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath, "expected reduce input"},
		// Role public key reduce
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Targets, TestRootPrivKeyFilepath, TestTargetsPubKeyFilepath, "expected reduce input"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Snapshot, TestRootPrivKeyFilepath, TestSnapshotPubKeyFilepath, "expected reduce input"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Timestamp, TestRootPrivKeyFilepath, TestTimestampPubKeyFilepath, "expected reduce input"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Targets, TestRootPrivKeyFilepath, TestTargetsPubKeyTwoFilepath, "expected reduce input"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Snapshot, TestRootPrivKeyFilepath, TestSnapshotPubKeyTwoFilepath, "expected reduce input"},
		{TestOutputMetadataDir, ChangeThresholdActionReduce, Timestamp, TestRootPrivKeyFilepath, TestTimestampPubKeyTwoFilepath, "expected reduce input"},

		{TestOutputMetadataDir, ChangeThresholdActionAdd, Targets, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, "expected add input"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Snapshot, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, "expected add input"},
		{TestOutputMetadataDir, ChangeThresholdActionAdd, Timestamp, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, "expected add input"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldPass {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 1
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath},
				Targets:   {TestTargetsPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath},
				Snapshot:  {TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath},
				Timestamp: {TestTimestampPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath},
			},
			rootThreshhold:     2,
			targetsThreshold:   2,
			snapshotThreshold:  2,
			timestampThreshold: 2,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. Change threshold
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			ChangeThresholdVerb,
			fmt.Sprintf("--%s=%s", ChangeThresholdMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", ChangeThresholdAction, c.action),
			fmt.Sprintf("--%s=%s", ChangeThresholdRole, c.role),
			fmt.Sprintf("--%s=%s", ChangeThresholdRootPrivkeyFilepath, c.rootPrivkeyFilepath),
			fmt.Sprintf("--%s=%s", ChangeThresholdRolePrivkeyFilepath, c.rolePrivkeyFilepath),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] != ChangeThresholdSucceeded {
			t.Fatal(lines)
		}
		// Verification should fail, successful sign will output a new root metadata file,
		// however with only 1 root signature (1/2 threshold)
		err = verifyAllRolesTestHelper(c.metadataDir)
		if err == nil {
			t.Fatal(err)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}

func TestVerifyUpdateSignaturesShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		respositoryDir  string
		metadataDir     string
		caseDescription string
	}{
		{TestRepoDir, TestOutputMetadataDir, "inadequate signatures"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 2
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath},
				Targets:   {TestTargetsPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath},
				Snapshot:  {TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath},
				Timestamp: {TestTimestampPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath},
			},
			rootThreshhold:     2,
			targetsThreshold:   2,
			snapshotThreshold:  2,
			timestampThreshold: 2,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. Update with 1 key for every role (threshold = 1/2)
		err = updateRepoMetadataTestHelper(configUpdate{
			repositoryDir:            TestRepoDir,
			metadataDir:              TestOutputMetadataDir,
			targetsPrivkeyFilepath:   TestTargetsPrivKeyFilepath,
			snapshotPrivkeyFilepath:  TestSnapshotPrivKeyFilepath,
			timestampPrivkeyFilepath: TestTimestampPrivKeyFilepath,
			expireIn:                 365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 3. Verification should fail
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			VerifyVerb,
			fmt.Sprintf("--%s=%s", VerifyRepositoryDir, c.respositoryDir),
			fmt.Sprintf("--%s=%s", VerifyMetadataDir, c.metadataDir),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] == VerifySucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestVerifyChangeThresholdSignaturesShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		respositoryDir  string
		metadataDir     string
		caseDescription string
	}{
		{TestRepoDir, TestOutputMetadataDir, "inadequate signatures"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 2
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath},
				Targets:   {TestTargetsPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath},
				Snapshot:  {TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath},
				Timestamp: {TestTimestampPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath},
			},
			rootThreshhold:     2,
			targetsThreshold:   2,
			snapshotThreshold:  2,
			timestampThreshold: 2,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. Change threshold, creating new root metadata file (threshold = 1/2)
		err = changeThresholdTestHelper(configChangeThreshold{
			metadataDir:         c.metadataDir,
			action:              ChangeThresholdActionReduce,
			role:                Targets,
			rootPrivkeyFilepath: TestRootPrivKeyFilepath,
			rolePrivkeyFilepath: TestTargetsPubKeyFilepath,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 3. Verification should fail
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			VerifyVerb,
			fmt.Sprintf("--%s=%s", VerifyRepositoryDir, c.respositoryDir),
			fmt.Sprintf("--%s=%s", VerifyMetadataDir, c.metadataDir),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] == VerifySucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestVerifyUpdateSignaturesShouldPass(t *testing.T) {
	casesShouldPass := []struct {
		respositoryDir  string
		metadataDir     string
		caseDescription string
	}{
		{TestRepoDir, TestOutputMetadataDir, "expected init update workflow"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldPass {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 1
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath /*, TestRootPrivKeyTwoFilepath*/},
				Targets:   {TestTargetsPrivKeyFilepath /*, TestTargetsPrivKeyTwoFilepath*/},
				Snapshot:  {TestSnapshotPrivKeyFilepath /*, TestSnapshotPrivKeyTwoFilepath*/},
				Timestamp: {TestTimestampPrivKeyFilepath /*, TestTimestampPrivKeyTwoFilepath*/},
			},
			rootThreshhold:     1,
			targetsThreshold:   1,
			snapshotThreshold:  1,
			timestampThreshold: 1,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. Update with 1 key for every role
		err = updateRepoMetadataTestHelper(configUpdate{
			repositoryDir:            TestRepoDir,
			metadataDir:              TestOutputMetadataDir,
			targetsPrivkeyFilepath:   TestTargetsPrivKeyFilepath,
			snapshotPrivkeyFilepath:  TestSnapshotPrivKeyFilepath,
			timestampPrivkeyFilepath: TestTimestampPrivKeyFilepath,
			expireIn:                 365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 3. Verification should pass
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			VerifyVerb,
			fmt.Sprintf("--%s=%s", VerifyRepositoryDir, c.respositoryDir),
			fmt.Sprintf("--%s=%s", VerifyMetadataDir, c.metadataDir),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] != VerifySucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestVerifyChangeThresholdSignaturesShouldPass(t *testing.T) {
	casesShouldPass := []struct {
		respositoryDir  string
		metadataDir     string
		caseDescription string
	}{
		{TestRepoDir, TestOutputMetadataDir, "expected init change threshold workflow"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldPass {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 1
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath /*, TestRootPrivKeyTwoFilepath*/},
				Targets:   {TestTargetsPrivKeyFilepath /*, TestTargetsPrivKeyTwoFilepath*/},
				Snapshot:  {TestSnapshotPrivKeyFilepath /*, TestSnapshotPrivKeyTwoFilepath*/},
				Timestamp: {TestTimestampPrivKeyFilepath /*, TestTimestampPrivKeyTwoFilepath*/},
			},
			rootThreshhold:     1,
			targetsThreshold:   1,
			snapshotThreshold:  1,
			timestampThreshold: 1,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 2. Change threshold, creating new root metadata file (threshold = 1/2)
		err = changeThresholdTestHelper(configChangeThreshold{
			metadataDir:         c.metadataDir,
			action:              ChangeThresholdActionReduce,
			role:                Targets,
			rootPrivkeyFilepath: TestRootPrivKeyFilepath,
			rolePrivkeyFilepath: TestTargetsPubKeyFilepath,
		})
		if err != nil {
			t.Fatal(err)
		}
		// 3. Verification should pass
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			VerifyVerb,
			fmt.Sprintf("--%s=%s", VerifyRepositoryDir, c.respositoryDir),
			fmt.Sprintf("--%s=%s", VerifyMetadataDir, c.metadataDir),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] != VerifySucceeded {
			t.Fatal(lines)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}

func TestChangeRootKeySingleKeyShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		metadataDir          string
		action               string
		privkeyFilepath      string
		inputPrivkeyFilepath string
		// replacementPrivkeyFilepath string
		expire          uint16
		threshold       uint16
		caseDescription string
	}{
		// Reminder: Remove and replace actions accept public key for input!
		{TestOutputMetadataDir, ChangeRootKeyActionAdd, TestRootPrivKeyFilepath, TestTargetsPubKeyFilepath, 1, 1, "public key input"},
		{TestOutputMetadataDir, ChangeRootKeyActionAdd, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, 1, 1, "duplicate key"},
		{TestOutputMetadataDir, ChangeRootKeyActionRemove, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, 1, 1, "remove last root key"},
		// {TestOutputMetadataDir, ChangeRootKeyActionReplace, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, 1, "replacement key not provided"},
		// {TestOutputMetadataDir, ChangeRootKeyActionReplace, TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath, 1, "replacing non-existent key"},
		// {TestOutputMetadataDir, ChangeRootKeyActionReplace, TestRootPrivKeyFilepath, TestRootPubKeyFilepath, 1, "replacing sole key"},
		// {TestOutputMetadataDir, ChangeRootKeyActionReplace, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, 1, "replacing own"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 1
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath /*, TestRootPrivKeyTwoFilepath*/},
				Targets:   {TestTargetsPrivKeyFilepath /*, TestTargetsPrivKeyTwoFilepath*/},
				Snapshot:  {TestSnapshotPrivKeyFilepath /*, TestSnapshotPrivKeyTwoFilepath*/},
				Timestamp: {TestTimestampPrivKeyFilepath /*, TestTimestampPrivKeyTwoFilepath*/},
			},
			rootThreshhold:     1,
			targetsThreshold:   1,
			snapshotThreshold:  1,
			timestampThreshold: 1,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			ChangeRootKeyVerb,
			fmt.Sprintf("--%s=%s", ChangeRootKeyMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", ChangeRootKeyAction, c.action),
			fmt.Sprintf("--%s=%s", ChangeRootKeyPrivkeyFilepath, c.privkeyFilepath),
			fmt.Sprintf("--%s=%s", ChangeRootKeyInputPrivkeyFilepath, c.inputPrivkeyFilepath),
			// fmt.Sprintf("--%s=%s", ChangeRootKeyReplacementPrivkeyFilepath, c.replacementPrivkeyFilepath),
			fmt.Sprintf("--%s=%d", ChangeRootKeyExpire, c.expire),
			fmt.Sprintf("--%s=%d", ChangeRootKeyThreshold, c.threshold),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] == ChangeRootKeySucceeded {
			t.Fatal(lines)
		}
		// Verify integrity
		err = verifyAllRolesTestHelper(c.metadataDir)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestChangeRootKeyDoubleKeyShouldFail(t *testing.T) {
	casesShouldFail := []struct {
		metadataDir          string
		action               string
		privkeyFilepath      string
		inputPrivkeyFilepath string
		// replacementPrivkeyFilepath string
		expire          uint16
		threshold       uint16
		caseDescription string
	}{
		// Reminder: Remove and replace actions accept public key for input!
		{TestOutputMetadataDir, ChangeRootKeyActionAdd, TestRootPrivKeyFilepath, TestTargetsPubKeyFilepath, 1, 1, "public key input"},
		{TestOutputMetadataDir, ChangeRootKeyActionAdd, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, 1, 1, "duplicate key"},
		{TestOutputMetadataDir, ChangeRootKeyActionAdd, TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath, 1, 1, "duplicate key"},
		{TestOutputMetadataDir, ChangeRootKeyActionRemove, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, 1, 1, "remove non-existent key"},
		{TestOutputMetadataDir, ChangeRootKeyActionRemove, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, 1, 1, "remove key that will be used to sign"},
		// {TestOutputMetadataDir, ChangeRootKeyActionReplace, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, "", 1, "replacement key not provided"},
		// {TestOutputMetadataDir, ChangeRootKeyActionReplace, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, TestRootPrivKeyTwoFilepath, 1, "replacing non-existent key"},
		// {TestOutputMetadataDir, ChangeRootKeyActionReplace, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, TestRootPrivKeyFilepath, 1, "replacing same"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldFail {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 1
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath},
				Targets:   {TestTargetsPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath},
				Snapshot:  {TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath},
				Timestamp: {TestTimestampPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath},
			},
			rootThreshhold:     2,
			targetsThreshold:   2,
			snapshotThreshold:  2,
			timestampThreshold: 2,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			ChangeRootKeyVerb,
			fmt.Sprintf("--%s=%s", ChangeRootKeyMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", ChangeRootKeyAction, c.action),
			fmt.Sprintf("--%s=%s", ChangeRootKeyPrivkeyFilepath, c.privkeyFilepath),
			fmt.Sprintf("--%s=%s", ChangeRootKeyInputPrivkeyFilepath, c.inputPrivkeyFilepath),
			// fmt.Sprintf("--%s=%s", ChangeRootKeyReplacementPrivkeyFilepath, c.replacementPrivkeyFilepath),
			fmt.Sprintf("--%s=%d", ChangeRootKeyExpire, c.expire),
			fmt.Sprintf("--%s=%d", ChangeRootKeyThreshold, c.threshold),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] == ChangeRootKeySucceeded {
			t.Fatal(lines)
		}
		// Verify integrity
		err = verifyAllRolesTestHelper(c.metadataDir)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestChangeRootKeySingleKeyShouldPass(t *testing.T) {
	casesShouldPass := []struct {
		metadataDir          string
		action               string
		privkeyFilepath      string
		inputPrivkeyFilepath string
		// replacementPrivkeyFilepath string
		expire          uint16
		threshold       uint16
		caseDescription string
	}{
		// Reminder: Remove and replace actions accept public key for input!
		{TestOutputMetadataDir, ChangeRootKeyActionAdd, TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath, 1, 1, "expected input"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldPass {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 1
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath /*, TestRootPrivKeyTwoFilepath*/},
				Targets:   {TestTargetsPrivKeyFilepath /*, TestTargetsPrivKeyTwoFilepath*/},
				Snapshot:  {TestSnapshotPrivKeyFilepath /*, TestSnapshotPrivKeyTwoFilepath*/},
				Timestamp: {TestTimestampPrivKeyFilepath /*, TestTimestampPrivKeyTwoFilepath*/},
			},
			rootThreshhold:     1,
			targetsThreshold:   1,
			snapshotThreshold:  1,
			timestampThreshold: 1,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			ChangeRootKeyVerb,
			fmt.Sprintf("--%s=%s", ChangeRootKeyMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", ChangeRootKeyAction, c.action),
			fmt.Sprintf("--%s=%s", ChangeRootKeyPrivkeyFilepath, c.privkeyFilepath),
			fmt.Sprintf("--%s=%s", ChangeRootKeyInputPrivkeyFilepath, c.inputPrivkeyFilepath),
			// fmt.Sprintf("--%s=%s", ChangeRootKeyReplacementPrivkeyFilepath, c.replacementPrivkeyFilepath),
			fmt.Sprintf("--%s=%d", ChangeRootKeyExpire, c.expire),
			fmt.Sprintf("--%s=%d", ChangeRootKeyThreshold, c.threshold),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] != ChangeRootKeySucceeded {
			t.Fatal(lines)
		}
		// Verify integrity
		err = verifyAllRolesTestHelper(c.metadataDir)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}
func TestChangeRootKeyDoubleKeyShouldPass(t *testing.T) {
	casesShouldPass := []struct {
		metadataDir          string
		action               string
		privkeyFilepath      string
		inputPrivkeyFilepath string
		// replacementPrivkeyFilepath string
		expire          uint16
		threshold       uint16
		caseDescription string
	}{
		// Reminder: Remove and replace actions accept public key for input!
		{TestOutputMetadataDir, ChangeRootKeyActionAdd, TestRootPrivKeyFilepath, TestTargetsPrivKeyFilepath, 1, 1, "expected input"},
		{TestOutputMetadataDir, ChangeRootKeyActionRemove, TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath, 1, 1, "remove key"},
		{TestOutputMetadataDir, ChangeRootKeyActionRemove, TestRootPrivKeyFilepath, TestRootPubKeyTwoFilepath, 1, 1, "remove with public key"},
		// {TestOutputMetadataDir, ChangeRootKeyActionReplace, TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath, TestTargetsPrivKeyFilepath, 1, "replace key"},
		// {TestOutputMetadataDir, ChangeRootKeyActionReplace, TestRootPrivKeyFilepath, TestRootPubKeyTwoFilepath, TestTargetsPrivKeyFilepath, 1, "replace with public key"},
	}

	out := new(bytes.Buffer)
	for _, c := range casesShouldPass {
		out.Reset()
		// 1. Init a new repo with every role's threshold = 1
		err := initRepoMetadataTestHelper(configInit{
			repositoryDir: TestRepoDir,
			outputDir:     c.metadataDir,
			rolesPrivkeyFilepaths: map[string][]string{
				Root:      {TestRootPrivKeyFilepath, TestRootPrivKeyTwoFilepath},
				Targets:   {TestTargetsPrivKeyFilepath, TestTargetsPrivKeyTwoFilepath},
				Snapshot:  {TestSnapshotPrivKeyFilepath, TestSnapshotPrivKeyTwoFilepath},
				Timestamp: {TestTimestampPrivKeyFilepath, TestTimestampPrivKeyTwoFilepath},
			},
			rootThreshhold:     2,
			targetsThreshold:   2,
			snapshotThreshold:  2,
			timestampThreshold: 2,
			expireIn:           365,
		})
		if err != nil {
			t.Fatal(err)
		}
		cmd := NewCommand()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{
			ChangeRootKeyVerb,
			fmt.Sprintf("--%s=%s", ChangeRootKeyMetadataDir, c.metadataDir),
			fmt.Sprintf("--%s=%s", ChangeRootKeyAction, c.action),
			fmt.Sprintf("--%s=%s", ChangeRootKeyPrivkeyFilepath, c.privkeyFilepath),
			fmt.Sprintf("--%s=%s", ChangeRootKeyInputPrivkeyFilepath, c.inputPrivkeyFilepath),
			// fmt.Sprintf("--%s=%s", ChangeRootKeyReplacementPrivkeyFilepath, c.replacementPrivkeyFilepath),
			fmt.Sprintf("--%s=%d", ChangeRootKeyExpire, c.expire),
			fmt.Sprintf("--%s=%d", ChangeRootKeyThreshold, c.threshold),
		})
		cmd.Execute()
		lines := convBufferToStrings(out)
		if lines[len(lines)-1] != ChangeRootKeySucceeded {
			t.Fatal(lines)
		}
		if c.action == ChangeRootKeyActionAdd {
			err = signTestHelper(configSign{
				metadataDir:     c.metadataDir,
				role:            Root,
				privkeyFilepath: TestRootPrivKeyTwoFilepath,
			})
			if err != nil {
				t.Fatal(err)
			}
		} else if c.action == ChangeRootKeyActionRemove {
			err = signTestHelper(configSign{
				metadataDir:     c.metadataDir,
				role:            Root,
				privkeyFilepath: TestRootPrivKeyTwoFilepath,
				forced:          true,
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		// Verify integrity
		err = verifyAllRolesTestHelper(c.metadataDir)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(lines)
		// Clear outputs
		os.RemoveAll(TestOutputDir)
		os.Mkdir(TestOutputDir, 0700) // user can write
	}
}

// Helper functions
func convBufferToStrings(bf *bytes.Buffer) []string {
	lines := strings.Split(bf.String(), "\n")
	return lines[:len(lines)-1]
}

func verifyAllRolesTestHelper(metaDir string) error {
	roles := repository.New()
	// Load root
	root := metadata.Root(datetime.ExpireIn(100))
	roles.SetRoot(root)
	rPaths, err := getRoleMetadataFilepathsFromDirTestHelper(metaDir, Root)
	if err != nil {
		return err
	}
	_, err = roles.Root().FromFile(rPaths[len(rPaths)-1])
	if err != nil {
		return err
	}

	// Load targets
	targets := metadata.Targets(datetime.ExpireIn(100))
	roles.SetTargets(Targets, targets)
	tPaths, err := getRoleMetadataFilepathsFromDirTestHelper(metaDir, Targets)
	if err != nil {
		return err
	}
	targets, err = roles.Targets(Targets).FromFile(tPaths[len(tPaths)-1])
	if err != nil {
		return err
	}

	// Load snapshot metadata file
	snapshot := metadata.Snapshot(datetime.ExpireIn(100))
	roles.SetSnapshot(snapshot)
	sPaths, err := getRoleMetadataFilepathsFromDirTestHelper(metaDir, Snapshot)
	if err != nil {
		return err
	}
	snapshot, err = roles.Snapshot().FromFile(sPaths[len(sPaths)-1])
	if err != nil {
		return err
	}

	// Load timestamp metadata file
	timestamp := metadata.Timestamp(datetime.ExpireIn(100))
	roles.SetTimestamp(timestamp)
	tsPaths, err := getRoleMetadataFilepathsFromDirTestHelper(metaDir, Timestamp)
	if err != nil {
		return err
	}
	timestamp, err = roles.Timestamp().FromFile(tsPaths[len(tsPaths)-1])
	if err != nil {
		return err
	}

	// Switch is not needed here, just for readability
	for _, name := range []string{Root, Timestamp, Snapshot, Targets} { // The ordering is IMPORTANT root > timestamp > snapshot > targets
		switch name {
		case Targets:
			err = roles.Root().VerifyDelegate(Targets, targets)
			if err != nil {
				return err
			}
			if isExp := roles.Targets(Targets).Signed.IsExpired(time.Now()); isExp {
				return fmt.Errorf("expired metadata")
			}
		case Snapshot:
			err = roles.Root().VerifyDelegate(Snapshot, snapshot)
			if err != nil {
				return err
			}
			if isExp := roles.Snapshot().Signed.IsExpired(time.Now()); isExp {
				return fmt.Errorf("expired metadata")
			}
		case Timestamp:
			err = roles.Root().VerifyDelegate(Timestamp, timestamp)
			if err != nil {
				return err
			}
			if isExp := roles.Timestamp().Signed.IsExpired(time.Now()); isExp {
				return fmt.Errorf("expired metadata")
			}
		case Root:
			err = roles.Root().VerifyDelegate(Root, root)
			if err != nil {
				return err
			}
			if isExp := roles.Root().Signed.IsExpired(time.Now()); isExp {
				return fmt.Errorf("expired metadata")
			}
		}
	}

	// ROOT > TIMESTAMP > SNAPSHOT > TARGETS
	rootBytes, err := roles.Root().ToBytes(true)
	if err != nil {
		return err
	}
	trustedMetadata, err := trustedmetadata.New(rootBytes)
	if err != nil {
		return err
	}

	// TIMESTAMP
	if timestampBytes, err := roles.Timestamp().ToBytes(true); err != nil {
		return err
	} else {
		if _, err = trustedMetadata.UpdateTimestamp(timestampBytes); err != nil {
			return err
		}
	}

	// SNAPSHOT
	if snapshotBytes, err := roles.Snapshot().ToBytes(true); err != nil {
		return err
	} else {
		if _, err = trustedMetadata.UpdateSnapshot(snapshotBytes, false); err != nil {
			return err
		}
	}

	// TARGETS
	if targetsBytes, err := roles.Targets(Targets).ToBytes(true); err != nil {
		return err
	} else {
		if _, err = trustedMetadata.UpdateTargets(targetsBytes); err != nil {
			return err
		}
	}

	// Begin root metadata file key continuity test
	previousRoot := metadata.Root(datetime.ExpireIn(placeholderExpireIn))
	_, err = previousRoot.FromFile(rPaths[0])
	if err != nil {
		return err

	}
	for _, filepath := range rPaths[1:] {
		root := metadata.Root(datetime.ExpireIn(placeholderExpireIn))
		_, err := root.FromFile(filepath)
		if err != nil {
			return err

		}
		err = previousRoot.VerifyDelegate(Root, root)
		if err != nil {
			return err

		}
		previousRoot = root
	}

	return nil
}

// Ascending order, last elem is the latest version of metadata file path
func getRoleMetadataFilepathsFromDirTestHelper(path string, roleName string) ([]string, error) {
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

func initRepoMetadataTestHelper(config configInit) error {
	_, err := filesystem.IsDirWritable(config.outputDir)
	if err != nil {
		if err = filesystem.MakeNewDir(config.outputDir); err != nil {
			return err
		}
	}

	roles := repository.New()

	targets := metadata.Targets(datetime.ExpireIn(365))
	roles.SetTargets(Targets, targets)
	snapshot := metadata.Snapshot(datetime.ExpireIn(365))
	roles.SetSnapshot(snapshot)
	timestamp := metadata.Timestamp(datetime.ExpireIn(365))
	roles.SetTimestamp(timestamp)
	root := metadata.Root(datetime.ExpireIn(365))
	roles.SetRoot(root)

	targetLocalFilepaths, targetFullFilepaths, err := filesystem.GetAllFilepathsInDir(config.repositoryDir)
	if err != nil {
		return err
	}
	for i, targetFullFilepath := range targetFullFilepaths {
		targetFileInfo, err := metadata.TargetFile().FromFile(targetFullFilepath)
		if err != nil {
			return err
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
		return err
	}

	// Record public keys info in root metadata file
	for _, name := range getRoles() {
		for _, key := range rolesKeys[name] {
			pubkey, err := metadata.KeyFromPublicKey(key.Public())
			if err != nil {
				return err
			}
			err = roles.Root().Signed.AddKey(pubkey, name)
			if err != nil {
				return err
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
				return err
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
				return err
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
			return err
		}
		succeededWrites = append(succeededWrites, filepath.Join(outputDir, filename))
	}

	return nil
}

func updateRepoMetadataTestHelper(config configUpdate) error {
	roles := repository.New()

	// Load old metadata files for all roles from files
	root := metadata.Root(datetime.ExpireIn(int(config.expireIn)))
	roles.SetRoot(root)
	rootFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Root)
	if err != nil {
		return err
	}
	_, err = roles.Root().FromFile(rootFilepaths[len(rootFilepaths)-1])
	if err != nil {
		return err
	}

	// Load old targets metadata file
	targets := metadata.Targets(datetime.ExpireIn(int(config.expireIn)))
	roles.SetTargets(Targets, targets)
	targetMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Targets)
	if err != nil {
		return err
	}
	oldTargets, err := roles.Targets(Targets).FromFile(targetMetadataFilepaths[len(targetMetadataFilepaths)-1])
	if err != nil {
		return err
	}

	// Load old snapshot metadata file
	snapshot := metadata.Snapshot(datetime.ExpireIn(int(config.expireIn)))
	roles.SetSnapshot(snapshot)
	snapshotMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Snapshot)
	if err != nil {
		return err
	}
	oldSnapshot, err := roles.Snapshot().FromFile(snapshotMetadataFilepaths[len(snapshotMetadataFilepaths)-1])
	if err != nil {
		return err
	}

	// Load old timestamp metadata file
	timestamp := metadata.Timestamp(datetime.ExpireIn(int(config.expireIn)))
	roles.SetTimestamp(timestamp)
	timestampMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Timestamp)
	if err != nil {
		return err
	}
	oldTimestamp, err := roles.Timestamp().FromFile(timestampMetadataFilepaths[len(timestampMetadataFilepaths)-1])
	if err != nil {
		return err
	}

	// Verify older version before proceeding to write the newer version
	for _, name := range getRoles() {
		switch name {
		case Targets:
			err = roles.Root().VerifyDelegate(Targets, oldTargets)
			if err != nil {
				return err
			}
		case Snapshot:
			err = roles.Root().VerifyDelegate(Snapshot, oldSnapshot)
			if err != nil {
				return err
			}
		case Timestamp:
			err = roles.Root().VerifyDelegate(Timestamp, oldTimestamp)
			if err != nil {
				return err
			}
		case Root:
			err = roles.Root().VerifyDelegate(Root, root)
			if err != nil {
				return err
			}
		}
	}

	// Generate new target metadata files from files in directory
	newTargets, err := metahelper.GenerateNewTargetsFromDir(config.repositoryDir, datetime.ExpireIn(7))
	if err != nil {
		return err
	}

	// Clear old signatures, update roles info, bump version
	roleNames := []string{Targets, Snapshot, Timestamp} // root metadata won't be touched
	for _, name := range roleNames {
		switch name {
		case Targets:
			roles.Targets(Targets).ClearSignatures()
			roles.SetTargets(Targets, newTargets)
			roles.Targets(Targets).Signed.Version = oldTargets.Signed.Version + 1
		case Snapshot:
			roles.Snapshot().ClearSignatures()
			roles.Snapshot().Signed.Meta[Targets+".json"] = metadata.MetaFile(roles.Targets(Targets).Signed.Version)
			roles.Snapshot().Signed.Version += 1
		case Timestamp:
			roles.Timestamp().ClearSignatures()
			roles.Timestamp().Signed.Meta[Snapshot+".json"] = metadata.MetaFile(roles.Snapshot().Signed.Version)
			roles.Timestamp().Signed.Version += 1
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
			return err
		}
		privkey, err := cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
		if err != nil {
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
			return fmt.Errorf("invalid key for role : %s", name)
		}
	}

	// Signing
	for _, name := range roleNames {
		key := keys[name]
		if key == nil {
			continue // If key not provided, skip
		}
		signer, err := signature.LoadSigner(key, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("fail to load signer for role: %s\n\terror: %w", name, err)
		}
		switch name {
		case Targets:
			roles.Targets(Targets).ClearSignatures()
			_, err = roles.Targets(Targets).Sign(signer)
			if err != nil {
				return fmt.Errorf("fail to sign metadata for role: %s\n\terror: %w", name, err)
			}
		case Snapshot:
			roles.Snapshot().ClearSignatures()
			_, err = roles.Snapshot().Sign(signer)
			if err != nil {
				return fmt.Errorf("fail to sign metadata for role: %s\n\terror: %w", name, err)
			}
		case Timestamp:
			roles.Timestamp().ClearSignatures()
			_, err = roles.Timestamp().Sign(signer)
			if err != nil {
				return fmt.Errorf("fail to sign metadata for role: %s\n\terror: %w", name, err)
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
			return err
		}
	}
	return nil
}

func changeThresholdTestHelper(config configChangeThreshold) error {
	// Load root private key
	bytes, err := filesystem.ReadBytesFromFile(config.rootPrivkeyFilepath)
	if err != nil {
		return err
	}
	rootPrivkey, err := cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
	if err != nil {
		return err
	}

	// Load role private key for `add` operation
	// Load role private OR public key for `reduce` operation
	isPub := false
	bytes, err = filesystem.ReadBytesFromFile(config.rolePrivkeyFilepath)
	if err != nil {
		return err
	}
	// Try to parse as private key
	rolePubkey := &rsa.PublicKey{}
	rolePrivkey, err := cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
	if err != nil {
		if config.action == ChangeThresholdActionAdd {
			return err
		} else if config.action == ChangeThresholdActionReduce {
			// If `reduce`, try to parse as public key
			rolePubkey, err = cryptography.ParseRsaPublicKeyFromPemStr(string(bytes))
			if err != nil {
				return err
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
		return err
	}
	_, err = roles.Root().FromFile(rootMetadataFilepaths[len(rootMetadataFilepaths)-1])
	if err != nil {
		return err
	}
	// Verify the old root metadata file has been signed (reached threshold)
	if err = roles.Root().VerifyDelegate(Root, roles.Root()); err != nil {
		return err
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
		return err
	}
	switch config.action {
	case ChangeThresholdActionAdd:
		roles.Root().Signed.Roles[config.role].Threshold += 1
		// Check duplicate
		if slices.Contains(roles.Root().Signed.Roles[config.role].KeyIDs, metaPubkey.ID()) {
			return err
		}
		// Add key to role
		if addErr := roles.Root().Signed.AddKey(metaPubkey, config.role); addErr != nil {
			return err
		}
	case ChangeThresholdActionReduce:
		roles.Root().Signed.Roles[config.role].Threshold -= 1
		if roles.Root().Signed.Roles[config.role].Threshold == 0 {
			return err
		}
		if revokeErr := roles.Root().Signed.RevokeKey(metaPubkey.ID(), config.role); revokeErr != nil {
			return err
		}
	}

	// Increase root metadata file version
	roles.Root().Signed.Version += 1
	roles.Root().ClearSignatures()

	// Load signer and sign
	signer, err := signature.LoadSigner(rootPrivkey, crypto.SHA256)
	if err != nil {
		return err
	}
	sig, err := roles.Root().Sign(signer)
	if err != nil {
		return err
	}

	// Verify if the correct root private key is used to sign
	if !slices.Contains(roles.Root().Signed.Roles[Root].KeyIDs, sig.KeyID) {
		return err
	}

	// Attempt write
	_, err = filesystem.IsDirWritable(config.metadataDir)
	if err != nil {
		return err
	}
	filename := fmt.Sprintf("%d.%s.json", roles.Root().Signed.Version, Root)
	err = roles.Root().ToFile(filepath.Join(config.metadataDir, filename), true)
	if err != nil {
		return err
	}

	return nil
}

func signTestHelper(config configSign) error {
	// Load private key
	bytes, err := filesystem.ReadBytesFromFile(config.privkeyFilepath)
	if err != nil {
		return err
	}
	key, err := cryptography.ParseRsaPrivateKeyFromPemStr(string(bytes))
	if err != nil {
		return err
	}
	signer, err := signature.LoadSigner(key, crypto.SHA256)
	if err != nil {
		return err
	}

	// Load root metadata file for verification purpose
	roles := repository.New()
	root := metadata.Root(datetime.ExpireIn(7))
	roles.SetRoot(root)
	rootMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, Root)
	if err != nil {
		return err
	}
	_, err = roles.Root().FromFile(rootMetadataFilepaths[len(rootMetadataFilepaths)-1])
	if err != nil {
		return err
	}

	// Load roles metadata from file
	roleMetadataFilepaths, err := metahelper.GetRoleMetadataFilepathsFromDir(config.metadataDir, config.role)
	if err != nil {
		return err
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
		return loadErr
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
		return signErr
	}

	// Check duplicate signature (old signature == new signature)
	switch config.role {
	case Targets:
		sigCount := map[string]int{}
		for _, sig := range roles.Targets(Targets).Signatures {
			sigCount[sig.KeyID] += 1
			if sigCount[sig.KeyID] > 1 {
				return fmt.Errorf("key count: %d, key id: %s", sigCount[sig.KeyID], sig.KeyID)
			}
		}
	case Snapshot:
		sigCount := map[string]int{}
		for _, sig := range roles.Snapshot().Signatures {
			sigCount[sig.KeyID] += 1
			if sigCount[sig.KeyID] > 1 {
				return fmt.Errorf("key count: %d, key id: %s", sigCount[sig.KeyID], sig.KeyID)
			}
		}
	case Timestamp:
		sigCount := map[string]int{}
		for _, sig := range roles.Timestamp().Signatures {
			sigCount[sig.KeyID] += 1
			if sigCount[sig.KeyID] > 1 {
				return fmt.Errorf("key count: %d, key id: %s", sigCount[sig.KeyID], sig.KeyID)
			}
		}
	case Root:
		sigCount := map[string]int{}
		for _, sig := range roles.Root().Signatures {
			sigCount[sig.KeyID] += 1
			if sigCount[sig.KeyID] > 1 {
				return fmt.Errorf("key count: %d, key id: %s", sigCount[sig.KeyID], sig.KeyID)
			}
		}
	}

	// Verify signature and ask for confirmation
	var verErr error
	if !config.forced && !slices.Contains(roles.Root().Signed.Roles[config.role].KeyIDs, signature.KeyID) {
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
		return verErr
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
		return writeErr
	}
	return nil
}
