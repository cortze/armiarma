package peering

import (
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/migalabs/armiarma/src/db"
)

// Strategy is the common interface the any desired Peering Strategy should follow
// TODO:  -Still waiting to be defined to make it official
type PeeringStrategy interface {
	// one channel to give the next peer, one to request the second one
	Run() chan db.Peer
	NextPeer()
	NewConnection(ConnectionStatus)
	NewDisconnection(peer.ID)
	Type() string
	//GetPeerBatch() []peer.ID
	Close()
}

// Connection Status is the struct that an active connection
// attempt done by the host will return to the peering strategy.
type ConnectionStatus struct {
	Peer       db.Peer   // TODO: right now just sending the entire info about the peer, (recheck after Peer struct subdivision)
	Timestamp  time.Time // Timestamp of when was the attempt done
	Successful bool      // Whether the connection attempt was successfully done or not
	RecError   error     // if the connection attempt reported any error, nil otherwise
	// TODO: More things to add in te future
}

type DisconnectionStatus struct {
	PeerID peer.ID
}
