// Main - contains the script to talk to different APIs
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RegexIP - Regex to identify an IP address
const RegexIP = "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$"

// IPMethods - List of all the methods to apply to IP assets
var IPMethods []string = []string{"iphub"}

// DomainMethods - List of all the methods to apply to domain assets
var DomainMethods []string = []string{""}

// DefUserAgent - Default user agent to use for all web requests
var DefUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"

// DefMethodDomain - Default method for domain to get more info
const DefMethodDomain = ""

// DefMethodIP - Default method for domain to get more info
const DefMethodIP = "iphub"

// IPHubKeyEnvVar - IPHub Key environment variable
const IPHubKeyEnvVar = "IPHUB_KEY"

// IPHubAPIURL - The URL for IPHub API to send request for getting info on IP
const IPHubAPIURL = "https://v2.api.iphub.info"

// IsAssetIP - Check if the supplied asset is an IP address?
func IsAssetIP(asset string, method string) bool {
	if method == "" {
		method = "regex"
	}

	found, _ := regexp.MatchString(RegexIP, asset)
	return found
}

// GetIPInfoIPHub - Function to make IPHub.info API request to get more info on
// IP asset
func GetIPInfoIPHub(asset string, ipHubAPIKey string) string {
	// Check if IPHub Key provided
	if ipHubAPIKey == "" {
		// Check os environ variables for the iphub API key
		ipHubAPIKey = os.Getenv(IPHubKeyEnvVar)
	}

	// API Key must be provided for IPHub, otherwise, no point in going further
	if ipHubAPIKey == "" {
		log.Fatalf("API Key not found for IPHub. Exiting.")
	}

	// Building the HTTP request template
	client := &http.Client{}

	// Build the URL to call to get info on IP
	url := fmt.Sprintf("%s/ip/%s", IPHubAPIURL, asset)

	// Setup a request template with the User Agent and API Key Header
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", DefUserAgent)
	req.Header.Set("X-Key", ipHubAPIKey)

	// Send web request
	resp, _ := client.Do(req)
	respBody, _ := ioutil.ReadAll(resp.Body)

	return string(respBody)
}

func main() {
	threadsPtr := flag.Int("t", 1,
		"Number of threads to use. When to set to 1, no concurrency.")
	methodDomainPtr := flag.String("md", "",
		"Method to operate on domain to info. Must be one of: "+
			strings.Join(DomainMethods, ","))
	methodIPPtr := flag.String("mi", "",
		"Method to operate on IP to get info. Must be one of: "+
			strings.Join(IPMethods, ","))
	ipHubKeyPtr := flag.String("ihk", "",
		"IPHub Key to use. If '', then read from env var: "+IPHubKeyEnvVar)
	sleepTimePtr := flag.Int("st", 3,
		"Sleep time between individual requests. Valid if num threads set to 1")
	flag.Parse()
	methodDomain := *methodDomainPtr
	methodIP := *methodIPPtr
	threads := *threadsPtr
	sleepTime := *sleepTimePtr
	ipHubKey := *ipHubKeyPtr

	if methodDomain == "" {
		log.Printf("Defaulting to method: %s for asset: domain", DefMethodDomain)
		methodDomain = DefMethodDomain
	}

	if methodIP == "" {
		log.Printf("Defaulting to method: %s for asset: IP", DefMethodIP)
		methodIP = DefMethodIP
	}

	// Get the asset to process
	assets := make(chan string)

	// Launch multiple threads to process the assets  listing
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)

		go func() {
			// Wait for assets to be processed
			defer wg.Done()

			ipInfo := ""
			for asset := range assets {
				// Check the asset type - is it an IP?
				if IsAssetIP(asset, "") {
					if methodIP == "iphub" {
						// Process IP address information provided
						ipInfo = GetIPInfoIPHub(asset, ipHubKey)

					} else {
						log.Fatalf("Unknown IP method: %s", methodIP)
					}

					// Display results to the user
					if ipInfo != "" {
						fmt.Printf("Info on IP: %s via method: %s\n%s\n\n", asset,
							methodIP, ipInfo)
					}

				} else {
					log.Fatalf("No support for domain related methods yet")
				}

				// Sleep for a few seconds before making next request
				if sleepTime > 0 {
					time.Sleep(time.Duration(sleepTime) * time.Second)
				}
			}
		}()
	}

	// Read assets to process from STDIN input
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := sc.Text()
		if line != "" {
			assets <- line
		}
	}

	// Read all assets, nothing more to add to the channel for processing
	close(assets)

	// Now, kill all running goroutines
	wg.Wait()
}
