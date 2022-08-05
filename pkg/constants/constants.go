// Copyright (C) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
package constants

import "time"

const (
	DefaultPerms755 = 0o755

	BaseDirName = ".avalanche-cli"

	SubnetEVMReleaseVersion   = "v0.2.7"
	AvalancheGoReleaseVersion = "v1.7.16"

	LatestAvagoReleaseURL = "https://api.github.com/repos/ava-labs/avalanchego/releases/latest"
	SubnetEVMReleaseURL   = "https://api.github.com/repos/ava-labs/subnet-evm/releases/latest"

	ServerRunFile      = "gRPCserver.run"
	AvalancheCliBinDir = "bin"
	RunDir             = "runs"
	ServiceDir         = "svc"
	ServiceFile        = "avalanchego.svc"
	SidecarSuffix      = "_sidecar.json"
	GenesisSuffix      = "_genesis.json"

	SidecarVersion = "1.1.0"

	MaxLogFileSize   = 4
	MaxNumOfLogFiles = 5
	RetainOldFiles   = 0 // retain all old log files

	RequestTimeout = 3 * time.Minute

	FujiAPIEndpoint    = "https://api.avax-test.network"
	MainnetAPIEndpoint = "https://api.avax.network"

	DefaultTokenName = "TEST"

	HealthCheckInterval = 100 * time.Millisecond

	// it's unlikely anyone would want to name a snapshot `default`
	// but let's add some more entropy
	SnapshotsDirName             = "snapshots"
	DefaultSnapshotName          = "default-1654102509"
	BootstrapSnapshotURL         = "https://github.com/ava-labs/avalanche-cli/raw/main/assets/bootstrapSnapshot.tar.gz"
	BootstrapSnapshotArchiveName = "bootstrapSnapshot.tar.gz"

	KeyDir    = "key"
	KeySuffix = ".pk"

	TimeParseLayout    = "2006-01-02 15:04:05"
	MinStakeDuration   = 24 * 14 * time.Hour
	MaxStakeDuration   = 24 * 365 * time.Hour
	MaxStakeWeight     = 100
	MinStakeWeight     = 1
	DefaultStakeWeight = 20

	// The absolute minimum is 25 seconds, but set to 1 minute to allow for
	// time to go through the command
	StakingStartLeadTime   = 1 * time.Minute
	StakingMinimumLeadTime = 25 * time.Second

	DefaultConfigFileName = ".avalanche-cli"
	DefaultConfigFileType = "json"

	CustomVMDir = "vms"
)
