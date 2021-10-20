package metrics

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	m_utils "github.com/migalabs/armiarma/src/metrics/utils"
	"github.com/migalabs/armiarma/src/utils"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
	log "github.com/sirupsen/logrus"
)

const DEFAULT_DELAY = 24 // hours of delay after each negative attempt with delay
var (
	DeprecationTime = 24 * time.Hour
)

// Stores all the information related to a peer
type Peer struct {
	PeerId        string
	NodeId        string
	UserAgent     string
	ClientName    string
	ClientOS      string //TODO:
	ClientVersion string
	Pubkey        string
	// Addrs         string
	Ip          string
	Country     string
	CountryCode string
	City        string
	Latency     float64

	// TODO: Store Enr
	// Latest ENR
	ENR *enode.Node

	MAddrs     []ma.Multiaddr
	Protocols []string

	ProtocolVersion string

	ConnectedDirection string
	IsConnected        bool
	Attempted          bool   // If the peer has been attempted to stablish a connection
	Succeed            bool   // If the connection attempt has been successful
	Attempts           uint64 // Number of attempts done
	Error              string // Type of error that we detected. TODO: We are just storing the last one

	Deprecated           bool        // Flag to rummarize whether the peer is longer valid for statistics or not
	WaitingDays          int         // number of days from last ping attempt that the crawler will wait to ping again
	NegativeConnAttempts []time.Time // List of dates when the peer retreived a negative connection attempt (if there is a possitive one, clean the struct)

	ConnectionTimes    []time.Time
	DisconnectionTimes []time.Time

	MetadataRequest bool  // If the peer has been attempted to request its metadata
	MetadataSucceed bool  // If the peer has been successfully requested its metadata
	LastExport      int64 //(timestamp in seconds of the last exported time (backup for when we are loading the Peer)

	// BeaconStatus
	BeaconStatus   BeaconStatusStamped
	BeaconMetadata BeaconMetadataStamped

	// Counters for the different topics
	MessageMetrics map[string]*MessageMetric
}

// Information regarding the messages received on a given topic
type MessageMetric struct {
	Count            uint64
	FirstMessageTime time.Time
	LastMessageTime  time.Time
}

func NewPeer(peerId string) Peer {
	pm := Peer{
		PeerId:               peerId,
		Error:                "None",
		NegativeConnAttempts: make([]time.Time, 0),
		ConnectionTimes:      make([]time.Time, 0),
		DisconnectionTimes:   make([]time.Time, 0),
		MessageMetrics:       make(map[string]*MessageMetric),
	}
	return pm
}

func (pm *Peer) ResetDynamicMetrics() {
	pm.Attempts = 0
	pm.MessageMetrics = make(map[string]*MessageMetric)
}

// returns true is peer has been deprecated for the further statistics
func (pm Peer) IsDeprecated() bool {
	return pm.Deprecated
}

// return waiting days that this peer has to wait untill next ping
func (pm Peer) DaysToWait() int {
	return pm.WaitingDays
}

// ReadyToConnect
// * This method evaluates if the given peer pm is ready to be connectd.
// * This means that the current time has exceeded the
// * lastAttempt + waiting time, so we have already waited enough
// @return True of False if we are in position to connect or not
func (pm Peer) ReadyToConnect() bool {

	lastConnectionAttempt := pm.ConnectionTimes[len(pm.ConnectionTimes)-1]
	delayTime := time.Duration(pm.DaysToWait()*DEFAULT_DELAY) * time.Hour

	// add both things to get the next time we would have to connect
	nextConnectionTime := lastConnectionAttempt.Add(delayTime).Unix()

	current_time := time.Now().Unix()

	// Compare time now with last connection plus waiting list
	if (current_time - nextConnectionTime) <= 0 {
		// If the current time is greater than the next connection time
		// it means connection time is in the past, so we can already connect

		// If both times are the same, then next connection time is the current time
		// so we are ready to connect again
		return true
	}
	return false // otherwise

}

// return the time of the last connection with this peer
func (pm Peer) LastAttempt() (t time.Time, err error) {
	if len(pm.NegativeConnAttempts) == 0 {
		err = errors.New("no negative connections for the peer")
		return
	}
	t = pm.NegativeConnAttempts[len(pm.NegativeConnAttempts)-1]
	err = nil
	return
}

// return the time of the last connection with this peer
func (pm Peer) FirstAttempt() (t time.Time, err error) {
	if len(pm.NegativeConnAttempts) == 0 {
		err = errors.New("no negative connections for the peer")
		return
	}
	t = pm.NegativeConnAttempts[0]
	err = nil
	return
}

func (pm *Peer) AddNegConnAtt() {
	t := time.Now()
	if len(pm.NegativeConnAttempts) > 0 {
		// check if the last Negative connection attempt is in the range to consider the peer deprecated
		tfirst := pm.NegativeConnAttempts[len(pm.NegativeConnAttempts)-1]
		diff := t.Unix() - tfirst.Unix()
		if time.Duration(diff)*time.Second >= DeprecationTime {
			pm.Deprecated = true
		}
	}
	pm.WaitingDays = 0
	pm.NegativeConnAttempts = append(pm.NegativeConnAttempts, t)
}

func (pm *Peer) AddNegConnAttWithPenalty() {
	t := time.Now()
	if len(pm.NegativeConnAttempts) > 0 {
		// check if the last Negative connection attempt is in the range to consider the peer deprecated
		tfirst := pm.NegativeConnAttempts[len(pm.NegativeConnAttempts)-1]
		diff := t.Unix() - tfirst.Unix()
		if time.Duration(diff)*time.Second >= DeprecationTime {
			pm.Deprecated = true
		}
	}
	// Update waiting days to the pruning process
	if pm.WaitingDays == 0 {
		pm.WaitingDays = 1
	} else {
		pm.WaitingDays = pm.WaitingDays * 2
	}
	pm.NegativeConnAttempts = append(pm.NegativeConnAttempts, t)
}

func (pm *Peer) AddPositiveConnAttempt() {
	pm.NegativeConnAttempts = make([]time.Time, 0)
	pm.Deprecated = false
	pm.WaitingDays = 0
}

// Register when a new connection was detected
func (pm *Peer) ConnectionEvent(direction string, time time.Time) {
	pm.ConnectionTimes = append(pm.ConnectionTimes, time)
	pm.IsConnected = true
	pm.ConnectedDirection = direction
}

// Register when a disconnection was detected
func (pm *Peer) DisconnectionEvent(time time.Time) {
	pm.DisconnectionTimes = append(pm.DisconnectionTimes, time)
	pm.IsConnected = false
	pm.ConnectedDirection = ""
}

// Register when a connection attempt was made. Note that there is some
// overlap with ConnectionEvent
func (pm *Peer) ConnectionAttemptEvent(succeed bool, err string) {
	pm.Attempts += 1
	if !pm.Attempted {
		pm.Attempted = true
	}
	if succeed {
		pm.Succeed = true
		pm.Error = "None"
	} else {
		pm.Error = m_utils.FilterError(err)
	}
}

// AddAddr
// * This method adds a new multiaddress in string format to the 
// * Addrs array. 
// @return Any error. Otherwise nil.
func (pm *Peer) AddAddr(input_addr string) error {
	new_ma, err := ma.NewMultiaddr(input_addr) // parse and format

	if err != nil {
		return err
	}
	pm.MAddrs = append(pm.MAddrs, ma.NewMultiaddr(input_addr))

}

// Fetch Peer information from another Peer info
func (pm *Peer) FetchPeerInfoFromPeer(newPeer Peer) {
	// Somehow weird to update the peerID, since it is going to be the same one
	pm.PeerId = getNonEmpty(pm.PeerId, newPeer.PeerId)
	pm.NodeId = getNonEmpty(pm.NodeId, newPeer.NodeId)
	// Check User Agent and derivated client type/version/OS
	pm.UserAgent = getNonEmpty(pm.UserAgent, newPeer.UserAgent)
	pm.ClientOS = getNonEmpty(pm.ClientOS, newPeer.ClientOS)
	if newPeer.ClientName != "" || pm.ClientName == "" {
		pm.ClientName = newPeer.ClientName
		pm.ClientVersion = newPeer.ClientVersion
	}
	pm.Pubkey = getNonEmpty(pm.Pubkey, newPeer.Pubkey)
	pm.MAddrs = getNonEmptyAddrArray(pm.MAddrs, newPeer.MAddrs)
	pm.Ip = getNonEmpty(pm.Ip, newPeer.Ip)
	if pm.City == "" || newPeer.City != "" {
		pm.City = newPeer.City
		pm.Country = newPeer.Country
	}
	if newPeer.Latency > 0 {
		pm.Latency = newPeer.Latency
	}
	// Metadata requested
	if !pm.MetadataRequest {
		pm.MetadataRequest = newPeer.MetadataRequest
	}
	if !pm.MetadataSucceed {
		pm.MetadataSucceed = newPeer.MetadataSucceed
	}
	// Beacon Metadata and Status
	if newPeer.BeaconMetadata != (BeaconMetadataStamped{}) {
		pm.BeaconMetadata = newPeer.BeaconMetadata
	}
	if newPeer.BeaconStatus != (BeaconStatusStamped{}) {
		pm.BeaconStatus = newPeer.BeaconStatus
	}
	// Aggregate connections and disconnections
	for _, time := range newPeer.ConnectionTimes {
		pm.ConnectionEvent(newPeer.ConnectedDirection, time)
	}
	for _, time := range newPeer.DisconnectionTimes {
		pm.DisconnectionEvent(time)
	}
}

// getNonEmpty compares whether the new string is not empty
// it returns the new one if its not empty or the old one it it was
func getNonEmpty(old string, new string) string {
	if new != "" {
		return new
	}
	return old
}

// getNonEmptyAddrArray compares whether the new mAddr array is not empty.
// If not empty, return the new one. If empty, return the old one
func getNonEmptyAddrArray(old []ma.Multiaddr, new []ma.Multiaddr) []ma.Multiaddr {
	if len(new) != 0 {
		return new
	}
	return old
}

// ExtractPublicAddr
// * This method loops over all multiaddress and extract the one that has
// * a public IP. There must be only one.
// @return the found multiaddress, nil if error
func (pm *Peer) ExtractPublicAddr() ma.Multiaddr {

	// loop over all multiaddresses in the array
	for _, temp_addr := range pm.MAddrs {
		temp_extracted_ip := utils.ExtractIPFromMAddr(temp_addr)

		// check if IP is public
		if utils.IsIPPublic(temp_extracted_ip) == true {
			// the IP is public
			return temp_addr
		}

	return nil // ended loop without returning a public address

}

// Update beacon Status of the peer
func (pm *Peer) UpdateBeaconStatus(bStatus beacon.Status) {
	pm.BeaconStatus = BeaconStatusStamped{
		Timestamp: time.Now(),
		Status:    bStatus,
	}
}

// Update beacon Metadata of the peer
func (pm *Peer) UpdateBeaconMetadata(bMetadata beacon.MetaData) {
	pm.BeaconMetadata = BeaconMetadataStamped{
		Timestamp: time.Now(),
		Metadata:  bMetadata,
	}
}

// Count the messages we get per topis and its first/last timestamps
func (pm *Peer) MessageEvent(topicName string, time time.Time) {
	if pm.MessageMetrics[topicName] == nil {
		pm.MessageMetrics[topicName] = &MessageMetric{}
		pm.MessageMetrics[topicName].FirstMessageTime = time
	}
	pm.MessageMetrics[topicName].LastMessageTime = time
	pm.MessageMetrics[topicName].Count++
}

// Calculate the total connected time based on con/disc timestamps
// Shifted some calculus to nanoseconds, Millisecons were leaving fields empty when exporting (less that 3 decimals)
func (pm *Peer) GetConnectedTime() float64 {
	var totalConnectedTime int64
	for _, conTime := range pm.ConnectionTimes {
		for _, discTime := range pm.DisconnectionTimes {
			singleConnectionTime := discTime.Sub(conTime)
			if singleConnectionTime >= 0 {
				totalConnectedTime += int64(singleConnectionTime * time.Nanosecond)
				break
			} else {

			}
		}
	}
	return float64(totalConnectedTime) / 60000000000
}

// Get the number of messages that we got for a given topic. Note that
// the topic name is the shortened name i.e. BeaconBlock
func (pm *Peer) GetNumOfMsgFromTopic(shortTopic string) uint64 {
	msgMetric := pm.MessageMetrics[m_utils.ShortToFullTopicName(shortTopic)]
	if msgMetric != nil {
		return msgMetric.Count
	}
	return uint64(0)
}

// Get total of message rx from that peer
func (pm *Peer) GetAllMessagesCount() uint64 {
	totalMessages := uint64(0)
	for _, messageMetric := range pm.MessageMetrics {
		totalMessages += messageMetric.Count
	}
	return totalMessages
}

func (pm *Peer) ToCsvLine() string {
	// register if the peer was conected
	connStablished := "false"
	if len(pm.ConnectionTimes) > 0 {
		connStablished = "true"
	}
	csvRow := pm.PeerId + "," +
		pm.NodeId + "," +
		pm.UserAgent + "," +
		pm.ClientName + "," +
		pm.ClientVersion + "," +
		pm.Pubkey + "," +
		pm.ExtractPublicAddr().String() + "," +
		pm.Ip + "," +
		pm.Country + "," +
		pm.City + "," +
		strconv.FormatBool(pm.MetadataRequest) + "," +
		strconv.FormatBool(pm.MetadataSucceed) + "," +
		strconv.FormatBool(pm.Attempted) + "," +
		strconv.FormatBool(pm.Succeed) + "," +
		// right now we would just write TRUE if the peer was connected when exporting the metrics
		// However, we want to know if the peer established a connection with us
		// Measure it, as we said from the length of the connection times
		connStablished + "," +
		strconv.FormatBool(pm.IsConnected) + "," +
		strconv.FormatUint(pm.Attempts, 10) + "," +
		pm.Error + "," +
		fmt.Sprintf("%.6f", pm.Latency) + "," +
		fmt.Sprintf("%d", len(pm.ConnectionTimes)) + "," +
		fmt.Sprintf("%d", len(pm.DisconnectionTimes)) + "," +
		fmt.Sprintf("%.6f", pm.GetConnectedTime()) + "," +
		strconv.FormatUint(pm.GetNumOfMsgFromTopic("BeaconBlock"), 10) + "," +
		strconv.FormatUint(pm.GetNumOfMsgFromTopic("BeaconAggregateProof"), 10) + "," +
		strconv.FormatUint(pm.GetNumOfMsgFromTopic("VoluntaryExit"), 10) + "," +
		strconv.FormatUint(pm.GetNumOfMsgFromTopic("ProposerSlashing"), 10) + "," +
		strconv.FormatUint(pm.GetNumOfMsgFromTopic("AttesterSlashing"), 10) + "," +
		strconv.FormatUint(pm.GetAllMessagesCount(), 10) + "\n"

	return csvRow
}

func (pm *Peer) LogPeer() {
	log.WithFields(log.Fields{
		"PeerId":        pm.PeerId,
		"NodeId":        pm.NodeId,
		"UserAgent":     pm.UserAgent,
		"ClientName":    pm.ClientName,
		"ClientOS":      pm.ClientOS,
		"ClientVersion": pm.ClientVersion,
		"Pubkey":        pm.Pubkey,
		"Addrs":         pm.MAddrs,
		"Ip":            pm.Ip,
		"Country":       pm.Country,
		"City":          pm.City,
		"Latency":       pm.Latency,
	}).Info("Peer Info")
}

// BEACON METADATA

// Basic BeaconMetadata struct that includes the timestamp of the received beacon metadata
type BeaconMetadataStamped struct {
	Timestamp time.Time
	Metadata  beacon.MetaData
}

// BEACON STATUS

//  Basic BeaconMetadata struct that includes The timestamp of the received beacon Status
type BeaconStatusStamped struct {
	Timestamp time.Time
	Status    beacon.Status
}
