// Copyright (C) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
package infracmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ava-labs/avalanche-cli/pkg/key"
	"github.com/ava-labs/avalanche-cli/pkg/models"
	"github.com/ava-labs/avalanche-cli/pkg/prompts"
	"github.com/ava-labs/avalanche-cli/pkg/subnet"
	"github.com/ava-labs/avalanche-cli/pkg/ux"
	"github.com/ava-labs/avalanche-network-runner/utils"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/staking"
	"github.com/ava-labs/avalanchego/utils/crypto"
	"github.com/ava-labs/avalanchego/utils/formatting"
	"github.com/ava-labs/avalanchego/utils/formatting/address"
	"github.com/ava-labs/avalanchego/utils/units"
	"github.com/ava-labs/avalanchego/vms/secp256k1fx"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/spf13/cobra"
)

var (
	nodeNum        int
	keyName        string
	nodeNamePrefix string
	deployTestnet  bool
	deployMainnet  bool
	useLedger      bool
)

var keyFactory = new(crypto.FactorySECP256K1R)

// avalanche pregenerate all
func newPregenerateAllCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "all [subnetName]",
		Short:        "Pregenerate ",
		Long:         `This command allows to set both config files.`,
		SilenceUsage: true,
		RunE:         all,
		Args:         cobra.ExactArgs(1),
	}

	cmd.Flags().IntVar(&nodeNum, "num-nodes", 5, "number of nodes in the subnet")
	cmd.Flags().StringVar(&keyName, "key", "", "the key to use to issue transactions")

	cmd.Flags().BoolVar(&deployTestnet, "fuji", false, "deploy on `fuji` (alias for `testnet`)")
	cmd.Flags().BoolVar(&deployTestnet, "testnet", false, "deploy on `testnet` (alias for `fuji`)")
	cmd.Flags().BoolVar(&deployMainnet, "mainnet", false, "deploy on `mainnet`")
	return cmd
}

func all(cmd *cobra.Command, args []string) error {
	var err error

	subnetName := args[0]
	vmID, err := utils.VMID(subnetName)
	if err != nil {
		return err
	}

	if keyName == "" {
		keyName, err = app.Prompt.CaptureString("What key from Secrets Manager should be used for this deploy?")
		if err != nil {
			return err
		}
	}

	svc := secretsmanager.New(session.New(
		&aws.Config{
			Region: aws.String("us-east-1"),
		},
	))

	// create NodeIDs
	certs := make([]*tls.Certificate, nodeNum)
	for i := 0; i < nodeNum; i++ {
		cert, key, err := staking.NewCertAndKeyBytes()
		if err != nil {
			return err
		}

		crt, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return err
		}
		crt.Leaf, err = x509.ParseCertificate(crt.Certificate[0])
		if err != nil {
			return err
		}
		certs[i] = &crt

		nodeName := fmt.Sprintf(nodeNamePrefix+"-%d", i)

		if err := createSecretForCerts(cert, key, svc, subnetName, nodeName); err != nil {
			return fmt.Errorf("failed to create cert and key for node %d: %w", i, err)
		}
	}

	var network models.Network
	switch {
	case deployTestnet:
		network = models.Fuji
	case deployMainnet:
		network = models.Mainnet
	}

	// no flags, ask user
	if network == models.Undefined {
		networkStr, err := app.Prompt.CaptureList(
			"Choose a network to add validator to.",
			[]string{models.Fuji.String(), models.Mainnet.String()},
		)
		if err != nil {
			return err
		}
		network = models.NetworkFromString(networkStr)
	}

	// here we know the network, use ledger or key?
	switch network {
	case models.Fuji:
		if !useLedger && keyName == "" {
			useLedger, keyName, err = prompts.GetFujiKeyOrLedger(app.Prompt, app.GetKeyDir())
			if err != nil {
				return err
			}
		}
	case models.Mainnet:
		useLedger = true
	default:
		return errors.New("unsupported network")
	}

	kc, err := getKeychain(keyName, svc)
	if err != nil {
		return fmt.Errorf("failed with keychain: %w", err)
	}

	threshold := uint32(1)
	addr := kc.Addresses().List()
	controlKeys := make([]string, len(addr))
	nID, err := network.NetworkID()
	if err != nil {
		return fmt.Errorf("failed getting netID: %w", err)
	}
	hrp := key.GetHRP(nID)
	for i, k := range addr {
		controlKeys[i], err = address.Format("P", hrp, k[:])
	}

	subnetAuthKeys := controlKeys
	chainGenesis, err := os.ReadFile("/home/fabio/prj/avalabs/cfg/subnet-evm.genesis.json")
	if err != nil {
		return err
	}

	// deploy to public network
	deployer := subnet.NewPublicDeployer(app, useLedger, kc, network)

	// addValidators
	amt := uint64(1 * units.Avax)
	start := time.Now().Add(5 * time.Minute)
	duration := 200 * 24 * time.Hour
	delFee := uint32(100_000)
	rewardsOwner := &secp256k1fx.OutputOwners{
		Threshold: 1,
		Addrs:     addr,
	}
	for i := 0; i < nodeNum; i++ {
		nodeID := ids.NodeIDFromCert(certs[i].Leaf)
		_, err := deployer.AddValidator(nodeID, amt, start, duration, delFee, rewardsOwner)
		if err != nil {
			return err
		}
		ux.Logger.PrintToUser("Added validator with NodeID %s to validate primary network", nodeID.String())
	}

	// wait until became validator
	ux.Logger.PrintToUser("waiting until validators are validating...")
	time.Sleep(10 * time.Minute)
	ux.Logger.PrintToUser("done.")

	// deploy subnet
	_, subnetID, blockchainID, _, err := deployer.Deploy(controlKeys, subnetAuthKeys, threshold, subnetName, chainGenesis)
	if err != nil {
		return fmt.Errorf("failed deploy: %w", err)
	}

	// addSubnetValidators
	weight := uint64(100)
	start = time.Now().Add(24 * time.Hour)
	duration = 180 * 24 * time.Hour
	for i := 0; i < nodeNum; i++ {
		nodeID := ids.NodeIDFromCert(certs[i].Leaf)
		_, _, err := deployer.AddSubnetValidator(subnetAuthKeys, subnetID, nodeID, weight, start, duration)
		if err != nil {
			return err
		}
		ux.Logger.PrintToUser("Added validator with NodeID %s to validate subnet %s", nodeID.String(), subnetName)
	}

	ux.Logger.PrintToUser("VMID: %s", vmID)
	ux.Logger.PrintToUser("SubnetID: %s", subnetID)
	ux.Logger.PrintToUser("BlockchainID: %s", blockchainID)
	return nil
}

func createSecretForCerts(
	cert, key []byte,
	svc *secretsmanager.SecretsManager,
	subnetName, nodeName string,
) error {
	certStringRep, err := formatting.Encode(formatting.Hex, cert)
	if err != nil {
		return err
	}
	certPath := fmt.Sprintf("subnet.%s.validator.%s.cert", subnetName, nodeName)
	certInput := &secretsmanager.CreateSecretInput{
		Description:  aws.String("Certificate and Key determining a NodeID for a new subnet node"),
		Name:         aws.String(certPath),
		SecretString: aws.String(certStringRep),
	}

	keyStringRep, err := formatting.Encode(formatting.Hex, key)
	if err != nil {
		return err
	}
	keyPath := fmt.Sprintf("subnet.%s.validator.%s.key", subnetName, nodeName)
	keyInput := &secretsmanager.CreateSecretInput{
		Description:  aws.String("Certificate and Key determining a NodeID for a new subnet node"),
		Name:         aws.String(keyPath),
		SecretString: aws.String(keyStringRep),
	}

	keyARN, err := createSecret(svc, keyInput)
	if err != nil {
		return err
	}

	certARN, err := createSecret(svc, certInput)
	if err != nil {
		return err
	}

	ux.Logger.PrintToUser("ARN for %s: %s", keyPath, keyARN)
	ux.Logger.PrintToUser("ARN for %s: %s", certPath, certARN)

	return nil
}

func createSecret(
	svc *secretsmanager.SecretsManager,
	input *secretsmanager.CreateSecretInput,
) (string, error) {
	result, err := svc.CreateSecret(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeInvalidParameterException:
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidRequestException:
				fmt.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
			case secretsmanager.ErrCodeLimitExceededException:
				fmt.Println(secretsmanager.ErrCodeLimitExceededException, aerr.Error())
			case secretsmanager.ErrCodeEncryptionFailure:
				fmt.Println(secretsmanager.ErrCodeEncryptionFailure, aerr.Error())
			case secretsmanager.ErrCodeResourceExistsException:
				fmt.Println(secretsmanager.ErrCodeResourceExistsException, aerr.Error())
			case secretsmanager.ErrCodeResourceNotFoundException:
				fmt.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			case secretsmanager.ErrCodeMalformedPolicyDocumentException:
				fmt.Println(secretsmanager.ErrCodeMalformedPolicyDocumentException, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			case secretsmanager.ErrCodePreconditionNotMetException:
				fmt.Println(secretsmanager.ErrCodePreconditionNotMetException, aerr.Error())
			case secretsmanager.ErrCodeDecryptionFailure:
				fmt.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return "", err
	}
	return *result.ARN, nil
}

func getKeychain(keyName string, svc *secretsmanager.SecretsManager) (*secp256k1fx.Keychain, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(keyName),
	}

	key, err := svc.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeResourceNotFoundException:
				fmt.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			case secretsmanager.ErrCodeInvalidParameterException:
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidRequestException:
				fmt.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
			case secretsmanager.ErrCodeDecryptionFailure:
				fmt.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.

			fmt.Println(err.Error())
		}
		return nil, err
	}

	keyRep := key.SecretString

	*keyRep = "21940f2ca55696fd38765dceafd9aaaabbf306e3f60aa83cb3100c76e3ac5f0b"

	skBytes, err := hex.DecodeString(*keyRep)
	if err != nil {
		return nil, fmt.Errorf("failed decoding: %w", err)
	}
	rpk, err := keyFactory.ToPrivateKey(skBytes)
	if err != nil {
		return nil, fmt.Errorf("failed converting to pk: %w", err)
	}
	privKey, ok := rpk.(*crypto.PrivateKeySECP256K1R)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %T", privKey)
	}

	keyChain := secp256k1fx.NewKeychain()
	keyChain.Add(privKey)

	return keyChain, nil
}
