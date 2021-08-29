package utils

import (
	"encoding/json"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net"
	"fmt"
	"strconv"
	"time"
)

// IP-API message structure
type IpApiMessage struct {
	Query       string `json:"query"`
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Region      string `json:"region"`
	RegionName  string `json:"regionName"`
	City        string `json:"city"`
	Zip         string `json:"zip"`
	Lat         string `json:"lat"`
	Lon         string `json:"lon"`
	Timezone    string `json:"timezone"`
	Isp         string `json:"isp"`
	Org         string `json:"org"`
	As          string `json:"as"`
}

// get IP, location country and City from the multiaddress of the peer on the peerstore
func GetLocationFromIP(ip string) (country string, city string, err error) {
	if IsPublic(net.ParseIP(ip)) != true {
		return "", "", errors.New(fmt.Sprintf("Given IP is private: %s", ip))
	}
	url := "http://ip-api.com/json/" + ip
	resp, err := http.Get(url)
	if err != nil {
		return "", "", errors.Wrap(err, "could not get country and city from ip")
	}

	attemptsLeft, _ := strconv.Atoi(resp.Header["X-Rl"][0])
	timeLeft, _ := strconv.Atoi(resp.Header["X-Ttl"][0])

	if attemptsLeft == 0 { // We have exceeded the limit of requests 45req/min
		time.Sleep(time.Duration(timeLeft) * time.Second)
		resp, err = http.Get(url)
		if err != nil {
			return "", "", errors.Wrap(err, "could not get country and city from ip")
		}
	}

	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	// Convert response body to Todo struct
	var ipApiResp IpApiMessage
	json.Unmarshal(bodyBytes, &ipApiResp)

	// Check if the status of the request has been succesful
	if ipApiResp.Status != "success" {
		return "", "", errors.Wrap(err, "could not get country and city from ip")
	}

	country = ipApiResp.Country
	city = ipApiResp.City

	// check if country and city are correctly imported
	if len(country) == 0 || len(city) == 0 {
		return "", "", errors.Wrap(err, "country or city are empty")
	}

	// return the received values from the received message
	return country, city, nil
}
