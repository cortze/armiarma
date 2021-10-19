package metrics

import (
	//log "github.com/sirupsen/logrus"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_Peer(t *testing.T) {
	// TODO
	require.Equal(t, 1, 1)
}

// TODO: Perhaps move to peerstore and test the whoe flow
func Test_MessageEvent(t *testing.T) {
	peer1 := NewPeer("peer1")

	// send some message to topic 1
	peer1.MessageEvent("topic1", parseTime("2021-08-23T01:00:00.000Z", t))
	peer1.MessageEvent("topic1", parseTime("2021-08-23T02:00:00.000Z", t))
	peer1.MessageEvent("topic1", parseTime("2021-08-23T03:00:00.000Z", t))

	// send some messages to topic 2
	peer1.MessageEvent("topic2", parseTime("2021-08-23T05:00:00.000Z", t))

	// assert first and last message times match
	require.Equal(t, peer1.MessageMetrics["topic1"].FirstMessageTime, parseTime("2021-08-23T01:00:00.000Z", t))
	require.Equal(t, peer1.MessageMetrics["topic1"].LastMessageTime, parseTime("2021-08-23T03:00:00.000Z", t))
	require.Equal(t, peer1.MessageMetrics["topic2"].FirstMessageTime, parseTime("2021-08-23T05:00:00.000Z", t))
	require.Equal(t, peer1.MessageMetrics["topic2"].LastMessageTime, parseTime("2021-08-23T05:00:00.000Z", t))

	// assert a total of 4 messages were recorded
	require.Equal(t, peer1.GetAllMessagesCount(), uint64(4))
}

func Test_GetConnectedTime(t *testing.T) {
	// simulate normal behaviour
	peer1 := NewPeer("peer1")
	// connect 59 seconds
	peer1.ConnectionEvent("inbound", parseTime("2021-08-23T01:00:00.000Z", t))
	peer1.DisconnectionEvent(parseTime("2021-08-23T01:00:59.000Z", t))
	// connect 1 second
	peer1.ConnectionEvent("inbound", parseTime("2021-08-25T01:00:00.000Z", t))
	peer1.DisconnectionEvent(parseTime("2021-08-25T01:00:01.000Z", t))
	conTime1 := peer1.GetConnectedTime()
	// total connection time 1 minute
	require.Equal(t, conTime1, float64(1))

	// simulate currently connected
	peer2 := NewPeer("peer2")
	// 5 second connection
	peer2.ConnectionEvent("inbound", parseTime("2021-08-23T01:00:00.000Z", t))
	peer2.DisconnectionEvent(parseTime("2021-08-23T01:00:05.000Z", t))
	// 1 second connection
	peer2.ConnectionEvent("inbound", parseTime("2021-09-25T01:00:00.000Z", t))
	peer2.DisconnectionEvent(parseTime("2021-09-25T01:00:01.000Z", t))
	// currently connected, no disc logged
	peer2.ConnectionEvent("inbound", parseTime("2021-10-23T01:00:00.000Z", t))
	conTime2 := peer2.GetConnectedTime()
	// total connection 6 seconds (6/60)
	require.Equal(t, conTime2, float64(0.1))

	// simulate a faulty, no disconnection
	peer3 := NewPeer("peer3")
	// connect 59 seconds
	peer3.ConnectionEvent("inbound", parseTime("2021-08-23T01:00:00.000Z", t))
	peer3.ConnectionEvent("inbound", parseTime("2021-08-25T02:00:00.000Z", t))
	peer3.ConnectionEvent("inbound", parseTime("2021-08-28T03:00:00.000Z", t))
	conTime3 := peer3.GetConnectedTime()
	require.Equal(t, conTime3, float64(0))

	// simulate a lost connection
	/* TODO: There is still an edge case not considered
	peer4 := NewPeer("peer4")
	peer4.ConnectionEvent("inbound", parseTime("2021-08-23T01:00:00.000Z", t))
	// this disconnection was lost
	peer4.ConnectionEvent("inbound", parseTime("2021-08-25T01:00:00.000Z", t))
	peer4.DisconnectionEvent(parseTime("2021-08-25T01:00:06.000Z", t))
	conTime4 := peer4.GetConnectedTime()
	require.Equal(t, conTime4, float64(0.1))
	*/
}

func parseTime(strTime string, t *testing.T) time.Time {
	parsedTime, err := time.Parse(time.RFC3339, strTime)
	require.NoError(t, err)
	return parsedTime
}

func Test_FetchPeerInfoFromPeer(t *testing.T) {
	// generate base peer
	peerBase := NewPeer("Peer1")

	peer2 := NewPeer("Peer1")
	peer2.NodeId = "Node1"
	peer2.UserAgent = "Prysm/v0.0.0"
	peer2.ClientName = "Prysm"
	peer2.ClientVersion = "v0.0.0"
	peer2.ClientOS = "Linux"
	peer2.Pubkey = "PubKey"
	peer2.Addrs = "/ip4/95.169.232.98/tcp/9000"
	peer2.Ip = "95.169.232.98"
	peer2.City = "City1"
	peer2.Country = "Country1"
	peer2.Latency = float64(2) / 1000
	peer2.MetadataRequest = true
	peer2.MetadataSucceed = true
	// Connected for 5 secs
	peer2.ConnectionEvent("inbound", parseTime("2021-08-23T01:00:00.000Z", t))
	peer2.DisconnectionEvent(parseTime("2021-08-23T01:00:05.000Z", t))
	peerBase.FetchPeerInfoFromPeer(peer2)

	// Peer Host/Node Info
	require.Equal(t, peerBase.PeerId, "Peer1")
	require.Equal(t, peerBase.NodeId, "Node1")
	require.Equal(t, peerBase.UserAgent, "Prysm/v0.0.0")
	require.Equal(t, peerBase.Addrs, "/ip4/95.169.232.98/tcp/9000")
	require.Equal(t, peerBase.Ip, "95.169.232.98")
	require.Equal(t, peerBase.Country, "Country1")
	require.Equal(t, peerBase.City, "City1")
	require.Equal(t, peerBase.Pubkey, "PubKey")
	require.Equal(t, float64(2)/1000, peerBase.Latency)
	require.Equal(t, peerBase.MetadataRequest, true)
	require.Equal(t, peerBase.MetadataSucceed, true)
	require.Equal(t, len(peerBase.ConnectionTimes), 1)
	require.Equal(t, len(peerBase.DisconnectionTimes), 1)
	conTime1 := peerBase.GetConnectedTime()
	// total connection time 1 minute
	require.Equal(t, conTime1, float64(5)/60)

	peerMod := NewPeer("Peer1")
	peerMod.UserAgent = "UpdateUser"
	peerMod.MetadataRequest = true
	peerMod.MetadataSucceed = false
	// Connected for 5 secs
	peerMod.ConnectionEvent("inbound", parseTime("2021-08-23T01:00:10.000Z", t))
	peerMod.DisconnectionEvent(parseTime("2021-08-23T01:00:15.000Z", t))
	peerBase.FetchPeerInfoFromPeer(peerMod)

	// Peer Host/Node Info
	require.Equal(t, peerBase.PeerId, "Peer1")
	require.Equal(t, peerBase.UserAgent, "UpdateUser")
	require.Equal(t, peerBase.MetadataRequest, true)
	require.Equal(t, peerBase.MetadataSucceed, true)
	require.Equal(t, len(peerBase.ConnectionTimes), 2)
	require.Equal(t, len(peerBase.DisconnectionTimes), 2)
	conTime2 := peerBase.GetConnectedTime()
	// total connection time 1 minute
	require.Equal(t, conTime2, float64(10)/60)
}
