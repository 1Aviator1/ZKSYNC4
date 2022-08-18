// Copyright (C) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
package subnetcmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ava-labs/avalanche-cli/internal/mocks"
	"github.com/ava-labs/avalanche-cli/pkg/application"
	"github.com/ava-labs/avalanche-cli/pkg/ux"
	"github.com/ava-labs/avalanchego/config"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/logging"
	"github.com/ava-labs/avalanchego/vms/platformvm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestIsNodeValidatingSubnet(t *testing.T) {
	assert := assert.New(t)
	nodeID := ids.GenerateTestNodeID()
	nonValidator := ids.GenerateTestNodeID()
	subnetID := ids.GenerateTestID()

	pClient := &mocks.PClient{}
	pClient.On("GetCurrentValidators", mock.Anything, mock.Anything, mock.Anything).Return(
		[]platformvm.ClientPrimaryValidator{
			{
				ClientStaker: platformvm.ClientStaker{
					NodeID: nodeID,
				},
			},
		}, nil)

	pClient.On("GetPendingValidators", mock.Anything, mock.Anything, mock.Anything).Return(
		[]interface{}{}, nil, nil).Once()

	interfaceReturn := make([]interface{}, 1)
	val := map[string]interface{}{
		"nodeID": nonValidator.String(),
	}
	interfaceReturn[0] = val
	pClient.On("GetPendingValidators", mock.Anything, mock.Anything, mock.Anything).Return(interfaceReturn, nil, nil)

	// first pass: should return true for the GetCurrentValidators
	isValidating, err := checkIsValidating(subnetID, nodeID, pClient)
	assert.NoError(err)
	assert.True(isValidating)

	// second pass: The nonValidator is not in current nor pending validators, hence false
	isValidating, err = checkIsValidating(subnetID, nonValidator, pClient)
	assert.NoError(err)
	assert.False(isValidating)

	// third pass: The second mocked GetPendingValidators applies, and this time
	// nonValidator is in the pending set, hence true
	isValidating, err = checkIsValidating(subnetID, nonValidator, pClient)
	assert.NoError(err)
	assert.True(isValidating)
}

func TestEditConfig(t *testing.T) {
	assert := assert.New(t)
	tmpDir := t.TempDir()
	testConfFile := filepath.Join(tmpDir, "test-config.json")
	subnetID := ids.GenerateTestID().String()
	networkID := fmt.Sprintf("%d", constants.FujiID)

	ux.NewUserLog(logging.NoLog{}, io.Discard)
	app = application.New()
	mockPrompt := &mocks.Prompter{}
	app.Prompt = mockPrompt

	mockPrompt.On("CaptureYesNo", mock.Anything).Return(false, errors.New("fake")).Once()
	err := editConfigFile(subnetID, networkID, testConfFile)
	assert.Error(err)
	assert.ErrorContains(err, "fake")
	assert.NoFileExists(testConfFile)

	mockPrompt.On("CaptureYesNo", mock.Anything).Return(false, nil).Once()
	err = editConfigFile(subnetID, networkID, testConfFile)
	assert.NoError(err)
	assert.NoFileExists(testConfFile)

	mockPrompt.On("CaptureYesNo", mock.Anything).Return(true, nil)
	f, err := os.Create(testConfFile)
	assert.NoError(err)
	_, err = f.Write([]byte("{Malformed JSON"))
	assert.NoError(err)
	err = editConfigFile(subnetID, networkID, testConfFile)
	assert.Error(err)
	assert.ErrorContains(err, "invalid character")
	err = os.Remove(testConfFile)
	assert.NoError(err)

	existing := map[string]string{
		"http-host":                  "192.168.42.42",
		"log-dir":                    "/some/file/path",
		"snow-avalanche-num-parents": "6",
		"log-level":                  "DEBUG",
	}

	existingConf, err := json.Marshal(&existing)
	assert.NoError(err)

	expected := copyMap(existing)
	expected[config.WhitelistedSubnetsKey] = subnetID
	runConfigTest(assert, existingConf, subnetID, networkID, testConfFile, expected)
	// check it contains what we expect
	err = os.Remove(testConfFile)
	assert.NoError(err)

	// now try with some existing entries
	oldNetID := "42"
	oldWhitelist := "29f2xLMWJcvDc13FcdizDaFuzyGdTYQHPnBY1H9XVworFyCC12,gw3FBdjCVibmhrNotkSKZetaAGHKVxPDEmacGkeuYqNypbjBk"

	existing[config.WhitelistedSubnetsKey] = oldWhitelist
	existing[config.NetworkNameKey] = oldNetID

	existingConf, err = json.Marshal(&existing)
	assert.NoError(err)

	expected[config.WhitelistedSubnetsKey] = oldWhitelist + "," + subnetID
	runConfigTest(assert, existingConf, subnetID, networkID, testConfFile, expected)
	err = os.Remove(testConfFile)
	assert.NoError(err)

	// now try with the subnetID already existing, no change should be made
	oldWhitelist = "29f2xLMWJcvDc13FcdizDaFuzyGdTYQHPnBY1H9XVworFyCC12," + subnetID + ",gw3FBdjCVibmhrNotkSKZetaAGHKVxPDEmacGkeuYqNypbjBk"
	existing[config.NetworkNameKey] = oldNetID // let's be pedantic and reset this to an old value
	existing[config.WhitelistedSubnetsKey] = oldWhitelist
	expected[config.WhitelistedSubnetsKey] = oldWhitelist

	existingConf, err = json.Marshal(&existing)
	assert.NoError(err)

	runConfigTest(assert, existingConf, subnetID, networkID, testConfFile, expected)
	// check it contains what we expect
	err = os.Remove(testConfFile)
	assert.NoError(err)
}

func copyMap(map1 map[string]string) map[string]string {
	newMap := map[string]string{}

	for k, v := range map1 {
		newMap[k] = v
	}

	return newMap
}

func runConfigTest(
	assert *assert.Assertions,
	conf []byte,
	subnetID string,
	networkID string,
	testConfFile string,
	expected map[string]string,
) {
	f, err := os.Create(testConfFile)
	assert.NoError(err)
	_, err = f.Write(conf)
	assert.NoError(err)
	err = editConfigFile(subnetID, networkID, testConfFile)
	assert.NoError(err)
	assert.FileExists(testConfFile)
	res, err := os.ReadFile(testConfFile)
	assert.NoError(err)

	var edited map[string]string
	// make sure it's valid JSON
	err = json.Unmarshal(res, &edited)
	assert.NoError(err)

	for k, v := range expected {
		assert.Contains(edited, k)
		assert.Equal(edited[k], v)
	}
	assert.Contains(edited, config.WhitelistedSubnetsKey)
	assert.Contains(edited, config.NetworkNameKey)
	assert.Equal(edited[config.NetworkNameKey], networkID)
}
