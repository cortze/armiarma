package info

import (
	"testing"

	"github.com/migalabs/armiarma/src/base"
	"github.com/stretchr/testify/require"
)

func Test_CustomInfoDataSuccess(t *testing.T) {
	stdOpts := base.LogOpts{
		Output:    "terminal",
		Formatter: "text",
	}
	info_object := NewCustomInfoData("../config/config_success.json", stdOpts)

	require.Equal(t, "127.0.0.1", info_object.GetIP().String())
	require.Equal(t, 100, info_object.GetTcpPort())
	require.Equal(t, 101, info_object.GetUdpPort())
	require.Equal(t, []string{"beacon_block", "beacon_aggregate_and_proof", "voluntary_exit", "proposer_slashing", "attester_slashing"}, info_object.GetTopicArray())
	require.Equal(t, "testnet", info_object.GetNetwork())
	require.Equal(t, "afcaaba0", info_object.GetForkDigest())
	require.Equal(t, "bsc_test", info_object.GetUserAgent())
	require.Equal(t, "026c60367b01fe3d7c7460bce1d585260ce465fa0abcb6e13619f88bf0dad54f", info_object.GetPrivKeyString())
	require.Equal(t, "debug", info_object.GetLogLevel())
	require.Equal(t, "/etc", info_object.GetDBPath())
	require.Equal(t, "Memory", info_object.GetDBType())
}

// Test_CustomInfoDataFail
// * This method tests the InfoData creation using a failing config file
// * All should be default as keys of the config should fail
func Test_CustomInfoDataFail(t *testing.T) {
	stdOpts := base.LogOpts{
		Output:    "terminal",
		Formatter: "text",
	}
	info_object := NewCustomInfoData("../config/config_fail.json", stdOpts)

	require.Equal(t, "0.0.0.0", info_object.GetIP().String())
	require.Equal(t, 9000, info_object.GetTcpPort())
	require.Equal(t, 9001, info_object.GetUdpPort())
	require.Equal(t, 5, len(info_object.GetTopicArray())) // at the moment there are five possible topics for one fork digest
	require.Equal(t, "mainnet", info_object.GetNetwork())
	require.Equal(t, "afcaaba0", info_object.GetForkDigest())
	require.Equal(t, "bsc_crawler", info_object.GetUserAgent())
	//require.Equal(t, "026c60367b01fe3d7c7460bce1d585260ce465fa0abcb6e13619f88bf0dad54f", info_object.GetPrivKeyString())
	require.Equal(t, "info", info_object.GetLogLevel())
	require.Equal(t, "./peerstore.db", info_object.GetDBPath())
	require.Equal(t, "bolt", info_object.GetDBType())

}
