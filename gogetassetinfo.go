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
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// RegexIP - Regex to identify an IP address
const RegexIP = "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$"

// IPMethods - List of all the methods to apply to IP assets
var IPMethods []string = []string{"iphub", "whois", "alienvault"}

// DomainMethods - List of all the methods to apply to domain assets
var DomainMethods []string = []string{"whois", "alienvault"}

// DefUserAgent - Default user agent to use for all web requests
var DefUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"

// DefMethodDomain - Default method for domain to get more info
const DefMethodDomain = "whois"

// DefMethodIP - Default method for domain to get more info
const DefMethodIP = "iphub"

// IPHubKeyEnvVar - IPHub Key environment variable
const IPHubKeyEnvVar = "IPHUB_KEY"

// IPHubAPIURL - The URL for IPHub API to send request for getting info on IP
const IPHubAPIURL = "https://v2.api.iphub.info"

// AlienVaultIndicatorURL - the URL to get the Alienvault indicators
const AlienVaultIndicatorURL = "https://otx.alienvault.com/api/v1/indicators"

// AlienVaultIPv4Sections - sections to get for IPv4 from AlienVault
const AlienVaultIPv4Sections = "general,reputation,geo,malware,url_list,passive_dns,http_scans"

// AlienVaultIPv6Sections - sections to get for IPv6 from AlienVault
const AlienVaultIPv6Sections = "general,reputation,geo,malware,url_list,passive_dns"

// AlienVaultDomainSections - sections to get for domain from AlienVault
const AlienVaultDomainSections = "general,geo,malware,url_list,whois,passive_dns"

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

// openbrowser - Opens a browser in relevant OS to display URL
func openbrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}

}

// execCmd - Execute command via shell and return the output
func execCmd(cmdToExec string) string {
	cmd := exec.Command("/bin/bash", "-c", cmdToExec)
	out, err := cmd.CombinedOutput()
	outStr := ""
	errStr := ""
	if out == nil {
		outStr = ""
	} else {
		outStr = string(out)
	}

	if err == nil {
		errStr = ""
	} else {
		errStr = string(err.Error())
	}

	totalOut := (outStr + "\n" + errStr)

	return totalOut
}

// GetWhoIs - Perform the Whois on the asset (IP/domain)
func GetWhoIs(asset string) string {
	cmdToExec := "whois " + asset
	return execCmd(cmdToExec)
}

// GetAlienVaultInfo - Get the alienvault information for asset (IP/IPv4, domain)
func GetAlienVaultInfo(asset string, assetType string) string {

	// Store the output
	out := ""

	// Prepare sections to get
	var sections []string
	var alienVaultURL string

	// Get the sections to get for alienvault
	if assetType == "ipv4" || assetType == "ip" {
		sections = strings.Split(AlienVaultIPv4Sections, ",")
		alienVaultURL = AlienVaultIndicatorURL + "/IPv4/" + asset
	} else if assetType == "domain" {
		sections = strings.Split(AlienVaultDomainSections, ",")
		alienVaultURL = AlienVaultIndicatorURL + "/domain/" + asset
	} else {
		log.Fatalf("Unknown assetType: %s", assetType)
	}

	// Prepare the HTTP client to make reequests to AlienVault
	client := &http.Client{}

	url := ""
	for _, section := range sections {
		url = alienVaultURL + "/" + section

		// Setup a request template with the User Agent and API Key Header
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", DefUserAgent)

		// Send web request
		resp, _ := client.Do(req)
		respBody, _ := ioutil.ReadAll(resp.Body)

		out += "\n" + string(respBody)
	}

	return out
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
			domainInfo := ""
			for asset := range assets {

				// let user know that we are getting info on asset
				log.Printf("Getting info on asset: %s", asset)

				// Check the asset type - is it an IP?
				if IsAssetIP(asset, "") {
					if methodIP == "iphub" {
						ipInfo = GetIPInfoIPHub(asset, ipHubKey)
					} else if methodIP == "whois" {
						ipInfo = GetWhoIs(asset)
					} else if methodIP == "alienvault" {
						ipInfo = GetAlienVaultInfo(asset, "ip")
					} else {
						log.Fatalf("Unknown IP method: %s", methodIP)
					}

					// Display results to the user
					if ipInfo != "" {
						fmt.Printf("[+] Info on IP: %s via method: %s\n%s\n\n", asset,
							methodIP, ipInfo)
					}

				} else {
					// Asset is domain - get asset information appropriately
					if methodDomain == "whois" {
						domainInfo = GetWhoIs(asset)
					} else if methodDomain == "alienvault" {
						domainInfo = GetAlienVaultInfo(asset, "domain")
					} else {
						log.Fatalf("No support for domain related methods yet")
					}

					if domainInfo != "" {
						fmt.Printf("[+] Info on domain: %s via method: %s\n%s\n\n", asset,
							methodDomain, domainInfo)
					}
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
