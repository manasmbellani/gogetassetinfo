package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/pretty"
)

// RegexIP - Regex to identify an IP address
const RegexIP = "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$"

// RegexDomain - Regex to identify domain addr
const RegexDomain = "^[a-zA-Z0-9_\\.\\-]+\\.[a-zA-Z0-9]{1,6}$"

// RegexMD5 - Regex to identify MD5
const RegexMD5 = "^[a-fA-F0-9]{32}$"

// RegexSHA1 - Regex to identify SHA-1
const RegexSHA1 = "^[a-fA-F0-9]{40}$"

// RegexSHA256 - Regex to identify SHA256
const RegexSHA256 = "^[a-fA-F0-9]{64}$"

// IPMethods - List of all the methods to apply to IP assets
var IPMethods []string = []string{"abuseip", "alienvault", "dnsptr", "iphub", "googlevpncheck", "ipinfo.io",
	"ipqualityscore", "robtex", "shodan", "scamalytics", "threatcrowd", "threatminer", "virustotal", "whois", "all"}

// DomainMethods - List of all the methods to apply to domain assets
var DomainMethods []string = []string{"alienvault", "dnsa", "dnsmx", "dnstxt",
	"resolve", "robtex", "virustotal", "urlscan.io", "phishtank", "threatcrowd", "threatminer", "whois", "all"}

// DefUserAgent - Default user agent to use for all web requests
var DefUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"

// DefMethodDomain - Default method for domain to get more info
const DefMethodDomain = "whois"

// DefMethodIP - Default method for domain to get more info
const DefMethodIP = "iphub"

// IPHubKeyEnvVar - IPHub Key environment variable
const IPHubKeyEnvVar = "IPHUB_KEY"

// URLScanIOURL - URLScan.io URL accessible
const URLScanIOURL = "https://urlscan.io/"

// IPHubAPIURL - The URL for IPHub API to send request for getting info on IP
const IPHubAPIURL = "https://v2.api.iphub.info"

// PhishtankURL - The URL of Phishtank
const PhishtankURL = "https://www.phishtank.com/"

// ScamalyticsURL - The URL for Scamalytics
const ScamalyticsURL = "https://scamalytics.com/ip"

// IPInfoAPIURL - The URL for ipinfo.io
const IPInfoAPIURL = "https://ipinfo.io"

// GoogleSearchURL - Ability to search URL being VPN via Google Search
const GoogleSearchURL = "https://www.google.com/search?q="

// VirusTotalURL - The URL for Virustotal submission
const VirusTotalURL = "https://www.virustotal.com/gui/{assetType}/{asset}/detection"

// IPQualityScoreURL - URL for the IP Quality Score website
const IPQualityScoreURL = "https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup"

// AlienVaultIndicatorURL - the URL to get the Alienvault indicators
const AlienVaultIndicatorURL = "https://otx.alienvault.com/api/v1/indicators"

// ShodanURL - the URL to get the info about the IP from
const ShodanURL = "https://www.shodan.io/host/"

// AlienVaultIPv4Sections - sections to get for IPv4 from AlienVault
const AlienVaultIPv4Sections = "general,reputation,geo,malware,url_list,passive_dns,http_scans"

// AlienVaultIPv6Sections - sections to get for IPv6 from AlienVault
const AlienVaultIPv6Sections = "general,reputation,geo,malware,url_list,passive_dns"

// AlienVaultDomainSections - sections to get for domain from AlienVault
const AlienVaultDomainSections = "general,geo,malware,url_list,whois,passive_dns"

// ThreatMinerURL - URL to get information about an IP address or Domain via ThreatMiner
const ThreatMinerURL = "https://www.threatminer.org/host.php?q="

// RobtexIPLookupURL - URL of the Robtex to lookup IP
const RobtexIPLookupURL = "https://www.robtex.com/ip-lookup/"

// RobtexDomainLookupURL - URL of the Robtex to lookup Domains
const RobtexDomainLookupURL = "https://www.robtex.com/dns-lookup/"

// ThreatCrowdIPURL - URL to get info about an IP via threatcrowd
const ThreatCrowdIPURL = "https://threatcrowd.org/ip.php?ip="

// ThreatCrowdDomainURL - URL get info about a domain via threatcrowd
const ThreatCrowdDomainURL = "https://threatcrowd.org/domain.php?domain="

// AbuseIPAPIKeyEnvVar - AbuseIP DB APIv2 Key environment variable
const AbuseIPAPIKeyEnvVar = "ABUSEIP_API_KEY"

// AbuseIPURL - URL to talk to get reputation of IP via AbuseIP DB
const AbuseIPURL = "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress="

// GetAssetType - Get the type of asset e.g ipv4, domain, md5, sha1, sha256
// or unknown
func GetAssetType(asset string) string {
	matched := false

	matched, _ = regexp.MatchString(RegexIP, asset)
	if matched {
		return "ipv4"
	}

	matched, _ = regexp.MatchString(RegexDomain, asset)
	if matched {
		return "domain"
	}

	matched, _ = regexp.MatchString(RegexMD5, asset)
	if matched {
		return "md5"
	}

	matched, _ = regexp.MatchString(RegexSHA1, asset)
	if matched {
		return "sha1"
	}

	matched, _ = regexp.MatchString(RegexSHA256, asset)
	if matched {
		return "sha256"
	}

	return "unknown"
}

// GetDNSTxt - Get DNS TXT records about a domain
func GetDNSTxt(domain string) string {
	txtout := ""
	txtrecords, _ := net.LookupTXT(domain)
	for _, txt := range txtrecords {
		txtout += string(txt) + "\n"
	}
	return txtout
}

// GetDNSA - Get DNS A record about domain
func GetDNSA(domain string) string {
	as, _ := net.LookupIP(domain)

	var ips []string
	for _, ip := range as {
		ips = append(ips, ip.String())
	}
	return fmt.Sprintf("%s %s", domain, strings.Join(ips, ","))

}

// GetDNSMX - Get DNS MX records about a domain
func GetDNSMX(domain string) string {
	mxout := ""
	mxrecords, _ := net.LookupMX(domain)
	for _, mx := range mxrecords {
		mxout += fmt.Sprintf("%s %d", mx.Host, mx.Pref) + "\n"
	}
	return mxout
}

// GetIPInfoIo - Get IP information via ipinfo.io
func GetIPInfoIo(asset string) string {

	// Building the HTTP request template
	client := &http.Client{}

	// Build the URL to call to get info on IP
	url := fmt.Sprintf(IPInfoAPIURL+"/%s/json", asset)

	// Setup a request template with the User Agent and API Key Header
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", DefUserAgent)

	// Send web request
	resp, _ := client.Do(req)
	respBody, _ := ioutil.ReadAll(resp.Body)

	return string(respBody)
}

// GetAbuseIPInfo - Get IP information via abuseip database through APIv2 API
func GetAbuseIPInfo(asset string, abuseIPKey string, abuseReportVerbose bool) string {

	if abuseIPKey == "" {
		// Check os environ variables for the iphub API key
		abuseIPKey = os.Getenv(AbuseIPAPIKeyEnvVar)
	}

	// API Key must be provided for IPHub, otherwise, no point in going further
	if abuseIPKey == "" {
		log.Fatalf("API Key not found for AbuseIP DB. Exiting.")
	}

	// Building the HTTP request template
	client := &http.Client{}

	// Setup a request template with the User Agent and API Key Header
	url := ""
	if !abuseReportVerbose {
		url = AbuseIPURL + asset
	} else {
		url = AbuseIPURL + asset + "&verbose=yes"
	}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", DefUserAgent)
	req.Header.Set("Key", abuseIPKey)
	req.Header.Set("Accept", "application/json")

	// Check if there were issues in create the post request object
	if err != nil {
		log.Fatalf("Error creating GET request object for AbuseIPDB. Error: %s", err.Error())
	}

	// Send web request
	resp, _ := client.Do(req)
	respBody, _ := ioutil.ReadAll(resp.Body)

	return string(pretty.Pretty(respBody))
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

	return string(pretty.Pretty(respBody))
}

// GetThreatMinerInfo - Get ThreatMiner Info about the domain/IP
func GetThreatMinerInfo(asset string) {

	// Build the ThreatMiner URL to open in the browser
	url := fmt.Sprintf("%s%s", ThreatMinerURL, asset)
	openbrowser(url)
}

// GetRobtexIPInfo - Get RobTex Info about domain/IP
func GetRobtexIPInfo(asset string) {
	// Build the Robtex URL to open in the browser
	url := fmt.Sprintf("%s%s", RobtexIPLookupURL, asset)
	openbrowser(url)
}

// GetRobtexDomainInfo - Get RobTex Info about domain/IP
func GetRobtexDomainInfo(asset string) {
	// Build the Robtex URL to open in the browser
	url := fmt.Sprintf("%s%s", RobtexDomainLookupURL, asset)
	openbrowser(url)
}

// GetThreatCrowdIPInfo - Get information about an IP via threatCrowd
func GetThreatCrowdIPInfo(asset string) {
	//Build the URL to open in browser
	url := fmt.Sprintf("%s%s", ThreatCrowdIPURL, asset)
	openbrowser(url)
}

// GetThreatCrowdDomainInfo - Get information about a domain via threatcrowd
func GetThreatCrowdDomainInfo(asset string) {
	// Build the URL to open in browser
	url := fmt.Sprintf("%s%s", ThreatCrowdDomainURL, asset)
	openbrowser(url)
}

// GetIPInfoScamalytics - Function opens a browser with URL to Scamalytics
func GetIPInfoScamalytics(asset string) {

	// Open Scamalytics for the given asset in a browser
	url := ScamalyticsURL + "/" + asset
	openbrowser(url)
}

// GetURLInfoURLScanIo - Open urlscan.io to scan the URL/domain
func GetURLInfoURLScanIo(asset string) string {

	// Open urlscan.io
	url := URLScanIOURL
	openbrowser(url)

	msg := fmt.Sprintf("[!] Supply the domain: %s to urlscan.io, and run 'Public Scan'\n", asset)
	return msg
}

// GetDomainInfoPhishtank - Open phishtank website to check the reputation of
// domain
func GetDomainInfoPhishtank(asset string) string {

	// Open phishtank website
	url := PhishtankURL
	openbrowser(url)

	msg := fmt.Sprintf("[!] Supply domain: %s to phishtank, and select 'Is it a phish?'\n", asset)
	return msg
}

// GetIPInfoShodanIo - Function to open browser to get info about the IP via
// Shodan.io
func GetIPInfoShodanIo(asset string) {
	url := ShodanURL + "/" + asset
	openbrowser(url)
}

// GetIPVPNInfo - Function to detect if IP might be a VPN via google search
func GetIPVPNInfo(asset string) {
	// Open Google Search
	url := fmt.Sprintf(GoogleSearchURL+"%s+vpn", asset)
	openbrowser(url)
}

// GetIPInfoIPQualityScore - Function opens a browser with URL to IPInfoIPQualityScore
func GetIPInfoIPQualityScore(asset string) {

	// Open Scamalytics for the given asset in a browser
	url := IPQualityScoreURL + "/" + asset
	openbrowser(url)
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

	// Determine the command to execute based on OS
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd.exe", "/c", cmdToExec)
	default:
		cmd = exec.Command("/bin/sh", "-c", cmdToExec)
	}

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

// GetDNSPtr - Get the PTR value for IP address
func GetDNSPtr(ipaddr string) string {
	hostname := ""

	const timeout = 10 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel() // important to avoid a resource leak

	var r net.Resolver
	names, err := r.LookupAddr(ctx, ipaddr)
	if err == nil && len(names) > 0 {
		hostname = names[0] // hostname
	}

	ipAddrToHostname := fmt.Sprintf("%s --> %s\n", ipaddr, hostname)
	return ipAddrToHostname
}

// GetVirustotalInfo - Perform Virustotal Search within the browser
func GetVirustotalInfo(asset string, assetType string) {
	// Get the specific asset type to supply in Virustotal
	vtAssetType := ""
	if assetType == "ipv4" {
		vtAssetType = "ip-address"
	} else if assetType == "domain" {
		vtAssetType = "domain"
	} else if assetType == "url" {
		vtAssetType = "url"
	} else {
		log.Printf("Unknown VT asset type: %s, asset: %s", assetType, asset)
	}

	// Build the VirusTotal URL
	vtURL := strings.ReplaceAll(VirusTotalURL, "{assetType}", vtAssetType)
	vtURL = strings.ReplaceAll(vtURL, "{asset}", asset)

	// Open the VirusTotal URL in browser
	openbrowser(vtURL)
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

		out += "\n" + string(pretty.Pretty(respBody))
	}

	return out
}

// displayProgress - Returns a statement to display progress, as test is conducted
func displayProgress(assetType string, asset string, methodname string) string {
	return fmt.Sprintf("[*] Getting info on %s: %s via '%s'\n", assetType, asset,
		methodname)
}

// shouldExecMethod - Determine if method should be executed depending
// on comma-sep list of methods to exec provided by user
func shouldExecMethod(methodsToExec string, methodID string) bool {
	shouldExecMethodFlag := false

	// Get list of all methods to execute
	methodsToExecList := strings.Split(methodsToExec, ",")

	// Check if any of the methods provided by user contains 'all' OR
	// our ID of our method to execute
	for _, method := range methodsToExecList {
		if method == methodID || method == "all" {
			shouldExecMethodFlag = true
			break
		}
	}

	return shouldExecMethodFlag
}

func main() {
	threadsPtr := flag.Int("t", 1,
		"Number of threads to use. When to set to 1, no concurrency.")
	methodDomainPtr := flag.String("md", "",
		"Method to operate on domain to info. Must be one of: "+
			strings.Join(DomainMethods, ", "))
	methodIPPtr := flag.String("mi", "",
		"Method to operate on IP to get info. Must be one of: "+
			strings.Join(IPMethods, ", "))
	ipHubKeyPtr := flag.String("ihk", "",
		"IPHub Key to use. If '', then read from env var: "+IPHubKeyEnvVar)
	sleepTimePtr := flag.Int("st", 3,
		"Sleep time between individual requests. Valid if num threads set to 1")
	abuseReportVerbosePtr := flag.Bool("ar", false,
		"Report the abuses for each IP by setting verbose flag for AbuseIP DB")
	flag.Parse()
	methodDomain := *methodDomainPtr
	methodIP := *methodIPPtr
	threads := *threadsPtr
	sleepTime := *sleepTimePtr
	ipHubKey := *ipHubKeyPtr
	abuseReportVerbose := *abuseReportVerbosePtr

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

				// Get the Asset Type e.g. ipv4, domain
				assetType := GetAssetType(asset)

				// Check the asset type - is it an IP?
				if assetType == "ipv4" {
					if shouldExecMethod(methodIP, "iphub") {
						ipInfo += displayProgress(assetType, asset, "iphub")
						ipInfo += "Review the 'block' value, where:\n"
						ipInfo += "    block:0 - Residential or Business IP (Legit IP)\n"
						ipInfo += "    block:1 - Non-residential IP (Suspicious IP!)\n"
						ipInfo += "    block:2 - Unknown (could be residential OR non-residential)\n\n"
						ipInfo += GetIPInfoIPHub(asset, ipHubKey) + "\n\n"
					}
					if shouldExecMethod(methodIP, "whois") {
						ipInfo += displayProgress(assetType, asset, "whois")
						ipInfo += GetWhoIs(asset) + "\n\n"
					}
					if shouldExecMethod(methodIP, "ipinfo.io") {
						ipInfo += displayProgress(assetType, asset, "ipinfo.io")
						ipInfo += GetIPInfoIo(asset) + "\n\n"
					}
					if shouldExecMethod(methodIP, "shodan") {
						ipInfo += displayProgress(assetType, asset, "shodan")
						GetIPInfoShodanIo(asset)
					}
					if shouldExecMethod(methodIP, "scamalytics") {
						ipInfo += displayProgress(assetType, asset, "scamalytics")
						GetIPInfoScamalytics(asset)
					}
					if shouldExecMethod(methodIP, "alienvault") {
						ipInfo += displayProgress(assetType, asset, "alienvault")
						ipInfo += GetAlienVaultInfo(asset, "ip") + "\n\n"
					}
					if shouldExecMethod(methodIP, "ipqualityscore") {
						ipInfo += displayProgress(assetType, asset, "ipqualityscore")
						GetIPInfoIPQualityScore(asset)
					}
					if shouldExecMethod(methodIP, "virustotal") {
						ipInfo += displayProgress(assetType, asset, "virustotal")
						GetVirustotalInfo(asset, assetType)
					}
					if shouldExecMethod(methodIP, "googlevpncheck") {
						ipInfo += displayProgress(assetType, asset, "googlevpncheck")
						GetIPVPNInfo(asset)
					}
					if shouldExecMethod(methodIP, "dnsptr") {
						ipInfo += displayProgress(assetType, asset, "dnsptr")
						ipInfo += GetDNSPtr(asset)
					}
					if shouldExecMethod(methodIP, "threatminer") {
						ipInfo += displayProgress(assetType, asset, "threatminer")
						GetThreatMinerInfo(asset)
					}
					if shouldExecMethod(methodIP, "robtex") {
						ipInfo += displayProgress(assetType, asset, "robtex")
						GetRobtexIPInfo(asset)
					}
					if shouldExecMethod(methodIP, "threatcrowd") {
						ipInfo += displayProgress(assetType, asset, "threatcrowd")
						GetThreatCrowdIPInfo(asset)
					}
					if shouldExecMethod(methodIP, "abuseip") {
						ipInfo += displayProgress(assetType, asset, "abuseip")
						ipInfo += GetAbuseIPInfo(asset, "", abuseReportVerbose)
					}
					// Display results to the user
					if ipInfo != "" {
						fmt.Printf("[+] Info on IP: %s via method: %s\n%s\n\n", asset,
							methodIP, ipInfo)
					}

				} else if assetType == "domain" {
					// Asset is domain - get asset information appropriately
					if shouldExecMethod(methodDomain, "whois") {
						domainInfo += displayProgress(assetType, asset, "whois")
						domainInfo += GetWhoIs(asset) + "\n\n"
					}
					if shouldExecMethod(methodDomain, "alienvault") {
						domainInfo += displayProgress(assetType, asset, "alienvault")
						domainInfo += GetAlienVaultInfo(asset, "domain") + "\n\n"
					}
					if shouldExecMethod(methodDomain, "dnstxt") {
						domainInfo += displayProgress(assetType, asset, "dnstxt")
						domainInfo += GetDNSTxt(asset) + "\n\n"
					}
					if shouldExecMethod(methodDomain, "dnsmx") {
						domainInfo += displayProgress(assetType, asset, "dnsmx")
						domainInfo += GetDNSMX(asset) + "\n\n"
					}
					if shouldExecMethod(methodDomain, "virustotal") {
						domainInfo += displayProgress(assetType, asset, "virustotal")
						GetVirustotalInfo(asset, assetType)
					}
					if shouldExecMethod(methodDomain, "dnsa") ||
						shouldExecMethod(methodDomain, "resolve") {
						domainInfo += displayProgress(assetType, asset, "dnsa")
						domainInfo += GetDNSA(asset) + "\n\n"
					}
					if shouldExecMethod(methodDomain, "urlscan.io") {
						domainInfo += displayProgress(assetType, asset, "urlscan.io")
						domainInfo += GetURLInfoURLScanIo(asset) + "\n\n"
					}
					if shouldExecMethod(methodDomain, "phishtank") {
						domainInfo += displayProgress(assetType, asset, "phishtank")
						domainInfo += GetDomainInfoPhishtank(asset) + "\n\n"
					}
					if shouldExecMethod(methodDomain, "threatminer") {
						domainInfo += displayProgress(assetType, asset, "threatminer")
						GetThreatMinerInfo(asset)
					}
					if shouldExecMethod(methodIP, "robtex") {
						domainInfo += displayProgress(assetType, asset, "robtex")
						GetRobtexDomainInfo(asset)
					}
					if shouldExecMethod(methodIP, "threatcrowd") {
						domainInfo += displayProgress(assetType, asset, "threatcrowd")
						GetThreatCrowdDomainInfo(asset)
					}

					if domainInfo != "" {
						fmt.Printf("[+] Info on domain: %s via method: %s\n%s\n\n", asset,
							methodDomain, domainInfo)
					}
				} else {
					log.Printf("Unknown asset type: %s for asset: %s",
						assetType, asset)
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
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			assets <- line
		}
	}

	// Read all assets, nothing more to add to the channel for processing
	close(assets)

	// Now, kill all running goroutines
	wg.Wait()
}
