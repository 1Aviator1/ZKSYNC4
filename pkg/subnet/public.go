// Copyright (C) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
package subnet

import (
	"context"
	"fmt"
	"time"

	"github.com/ava-labs/avalanche-cli/pkg/application"
	"github.com/ava-labs/avalanche-cli/pkg/constants"
	"github.com/ava-labs/avalanche-cli/pkg/key"
	"github.com/ava-labs/avalanche-cli/pkg/models"
	"github.com/ava-labs/avalanche-cli/pkg/ux"
	"github.com/ava-labs/avalanche-network-runner/utils"
	"github.com/ava-labs/avalanchego/ids"
	avago_constants "github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/formatting/address"
	"github.com/ava-labs/avalanchego/vms/platformvm/validator"
	"github.com/ava-labs/avalanchego/vms/secp256k1fx"
	"github.com/ava-labs/avalanchego/wallet/subnet/primary"
	"github.com/ava-labs/avalanchego/wallet/subnet/primary/common"
	"github.com/ava-labs/avalanchego/wallet/subnet/primary/keychain"
)

type PublicDeployer struct {
	LocalSubnetDeployer
	privKeyPath string
	network     models.Network
	app         *application.Avalanche
	useLedger   bool
}

func NewPublicDeployer(app *application.Avalanche, privKeyPath string, network models.Network, useLedger bool) *PublicDeployer {
	return &PublicDeployer{
		LocalSubnetDeployer: *NewLocalSubnetDeployer(app),
		app:                 app,
		privKeyPath:         privKeyPath,
		network:             network,
		useLedger:           useLedger,
	}
}

func (d *PublicDeployer) AddValidator(subnet ids.ID, nodeID ids.NodeID, weight uint64, startTime time.Time, duration time.Duration) error {
	wallet, _, err := d.loadWallet(subnet)
	if err != nil {
		return err
	}
	validator := &validator.SubnetValidator{
		Validator: validator.Validator{
			NodeID: nodeID,
			Start:  uint64(startTime.Unix()),
			End:    uint64(startTime.Add(duration).Unix()),
			Wght:   weight,
		},
		Subnet: subnet,
	}
	id, err := wallet.P().IssueAddSubnetValidatorTx(validator)
	if err != nil {
		return err
	}
	ux.Logger.PrintToUser("Transaction successful, transaction ID :%s", id)
	return nil
}

func (d *PublicDeployer) Deploy(controlKeys []string, threshold uint32, chain string, genesis []byte) (ids.ID, ids.ID, error) {
	wallet, api, err := d.loadWallet()
	if err != nil {
		return ids.Empty, ids.Empty, err
	}
	vmID, err := utils.VMID(chain)
	if err != nil {
		return ids.Empty, ids.Empty, fmt.Errorf("failed to create VM ID from %s: %w", chain, err)
	}

	subnetID, err := d.createSubnetTx(controlKeys, threshold, wallet)
	if err != nil {
		return ids.Empty, ids.Empty, err
	}
	ux.Logger.PrintToUser("Subnet has been created with ID: %s. Now creating blockchain...", subnetID.String())

	blockchainID, err := d.createBlockchainTx(chain, vmID, subnetID, genesis, wallet)
	if err != nil {
		return ids.Empty, ids.Empty, err
	}
	ux.Logger.PrintToUser("Endpoint for blockchain %q with VM ID %q: %s/ext/bc/%s/rpc", blockchainID.String(), vmID.String(), api, blockchainID.String())
	return subnetID, blockchainID, nil
}

func (d *PublicDeployer) loadWallet(preloadTxs ...ids.ID) (primary.Wallet, string, error) {
	ctx := context.Background()

	var (
		api       string
		networkID uint32
	)

	var (
		wallet primary.Wallet
		err    error
	)

	switch d.network {
	case models.Fuji:
		api = constants.FujiAPIEndpoint
		networkID = avago_constants.FujiID
		if d.useLedger {
			k, err := key.NewHard(networkID)
			if err != nil {
				return nil, "", err
			}
			lkc := keychain.NewLedgerKeychain(k.GetLedger())

			wallet, err = primary.NewLedgerWalletWithTxs(ctx, api, lkc, preloadTxs...)
			if err != nil {
				return nil, "", err
			}
		} else {
			sk, err := key.LoadSoft(networkID, d.privKeyPath)
			kc := sk.KeyChain()

			wallet, err = primary.NewWalletWithTxs(ctx, api, kc, preloadTxs...)
			if err != nil {
				return nil, "", err
			}
		}
		if err != nil {
			return nil, "", err
		}
	case models.Mainnet:
		api = constants.MainnetAPIEndpoint
		networkID = avago_constants.MainnetID
		k, err := key.NewHard(networkID)
		if err != nil {
			return nil, "", err
		}
		lkc := keychain.NewLedgerKeychain(k.GetLedger())

		wallet, err = primary.NewLedgerWalletWithTxs(ctx, api, lkc, preloadTxs...)
		if err != nil {
			return nil, "", err
		}
	default:
		return nil, "", fmt.Errorf("unsupported public network")
	}

	return wallet, api, nil
}

func (d *PublicDeployer) createBlockchainTx(chainName string, vmID, subnetID ids.ID, genesis []byte, wallet primary.Wallet) (ids.ID, error) {
	// TODO do we need any of these to be set?
	options := []common.Option{}
	fxIDs := make([]ids.ID, 0)
	return wallet.P().IssueCreateChainTx(subnetID, genesis, vmID, fxIDs, chainName, options...)
}

func (d *PublicDeployer) createSubnetTx(controlKeys []string, threshold uint32, wallet primary.Wallet) (ids.ID, error) {
	addrs, err := address.ParseToIDs(controlKeys)
	if err != nil {
		return ids.Empty, err
	}
	owners := &secp256k1fx.OutputOwners{
		Addrs:     addrs,
		Threshold: threshold,
		Locktime:  0,
	}
	opts := []common.Option{}
	return wallet.P().IssueCreateSubnetTx(owners, opts...)
}
