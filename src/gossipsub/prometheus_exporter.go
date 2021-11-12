package gossipsub

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migalabs/armiarma/src/gossipsub/blockchaintopics"
	promth "github.com/migalabs/armiarma/src/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// MessageMetrics
// * Summarizes all the metrics that could be obtained from the received msgs
// * Right now divided by topic and containing only the local counter between server ticker
type MessageMetrics struct {
	mutex     sync.RWMutex
	topicList map[string]*int32
}

// NewMessageMetrics
// @return intialized MessageMetrics struct
func NewMessageMetrics() MessageMetrics {
	return MessageMetrics{
		topicList: make(map[string]*int32, 0),
	}
}

// NewTopic
// @param name of the topic
// @return a possitive boolean if the topic was
// 		   already in Metrics, negative one otherwise
func (c *MessageMetrics) NewTopic(topic string) bool {
	counter := int32(0)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	_, exists := c.topicList[topic]
	if exists {
		return true
	}
	c.topicList[topic] = &counter
	return false
}

// AddMessgeToTopic
// @param gossipsub topic name
// @return curren message counter, or -1 if there was an error (non-existing topic)
func (c *MessageMetrics) AddMessgeToTopic(topic string) int32 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	v, exists := c.topicList[topic]
	if !exists {
		return int32(-1)
	}
	return atomic.AddInt32(v, 1)
}

// ResetTopic
// @param gossipsub topic name
// @return curren message counter, or -1 if there was an error (non-existing topic)
func (c *MessageMetrics) ResetTopic(topic string) int32 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	v, exists := c.topicList[topic]
	if !exists {
		return int32(-1)
	}
	return atomic.SwapInt32(v, int32(0))
}

// ResetAllTopics
// * resets all the topic counters to 0
// @return curren message counter, or -1 if there was an error (non-existing topic)
func (c *MessageMetrics) ResetAllTopics() error {
	for k, _ := range c.topicList {
		r := c.ResetTopic(k)
		if r < int32(0) {
			return fmt.Errorf("non existing topic %s in list", k)
		}
	}
	return nil
}

// GetTopicMsgs
// * Obtain the counter of messages from last ticker of given topic
// @return curren message counter, or -1 if there was an error (non-existing topic)
func (c *MessageMetrics) GetTopicMsgs(topic string) int32 {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	v, exists := c.topicList[topic]
	if !exists {
		return int32(-1)
	}
	return *v
}

// GetTotalMessages
// * Obtain the total of messages received from last ticker from all the topics
// @return total message counter, or -1 if there was an error (non-existing topic)
func (c *MessageMetrics) GetTotalMessages() int64 {
	var total int64
	for k, _ := range c.topicList {
		r := c.ResetTopic(k)
		if r < int32(0) {
			continue
		}
		total += int64(r)
	}
	return total
}

// ServeMetrics
// * This method will generate the metrics from GossipSub msg Metrics
// * and serve the values to the local prometheus instance
func (gs *GossipSub) ServeMetrics() {
	gsCtx := gs.Ctx()
	// tenerate a ticker
	ticker := time.NewTicker(promth.MetricLoopInterval)
	// register variables
	prometheus.MustRegister(ReceivedTotalMessages)
	prometheus.MustRegister(ReceivedMessages)

	// routine to loop
	go func() {
		for {
			select {
			case <-ticker.C:
				var totMsg int64
				msgPerMin := make(map[string]float64, 0)
				// get the total of the messages
				for k, _ := range gs.MessageMetrics.topicList {
					r := gs.MessageMetrics.GetTopicMsgs(k)
					if r < int32(0) {
						gs.Log.Warnf("Unable to get message count for topic %s", k)
						continue
					}
					msgC := (float64(r) / (promth.MetricLoopInterval.Seconds())) * 60 // messages per minute
					totMsg += int64(r)
					ReceivedMessages.WithLabelValues(blockchaintopics.Eth2TopicPretty(k)).Set(msgC)
					msgPerMin[blockchaintopics.Eth2TopicPretty(k)] = msgC
				}
				// get total of msgs
				tot := (float64(totMsg) / (promth.MetricLoopInterval.Seconds())) * 60 // messages per minute
				ReceivedTotalMessages.Set(tot)
				// reset the values
				err := gs.MessageMetrics.ResetAllTopics()
				if err != nil {
					gs.Log.Warnf("Unable to reset the gossip topic metrics. ", err.Error())
				}
				log.WithFields(log.Fields{
					"TopicMsg/min": msgPerMin,
					"TotalMsg/min": tot,
				}).Info("gossip metrics summary")

			case <-gsCtx.Done():
				// closing the routine in a ordened way
				ticker.Stop()
			}
		}
	}()
}
