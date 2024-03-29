# gogetassetinfo
Golang script that acts as a wrapper to get Reputation/information about domains/IP addresses through various methods.

Currently, results are printed directly to the output, and the raw results are displayed to the output.

## Setup
To install the script in `$GOPATH`, simply run: -

```
go get -u github.com/manasmbellani/gogetassetinfo
```

For `whois` module, the whois command should be either accessible within `$PATH` 
variable OR the whois binary should be available in the same folder as the location
of the `gogetassetinfo` binary.

## Supported API Sources
* Alienvault - Provide Alienvault pulse info in raw format.
* AbuseIPDB - Provides information about an IP address via the AbuseIPDB
* DNS Resolutions - provide DNS A, DNS TXT, DNS MX, resolution for domains and DNS PTR for IP addresses
* Google VPN Check - Perform a search to confirm if IP could belong to a VPN by performing a google search
* IpInfo.io - Provides info about an IP via `https://ipinfo.io`
* IPHub.info - API which provides IP types (residential (response: 0)/ proxy (response: 1) / unknown (response: 2)) for various ip addresses
* IPQualityScore.com - provides reputation about an IP via the ipqualityscore.com website
* Phishtank - Determine if domain name is a phish via Phistank API
* Robtex - Perform Domain or IP analysis via Robtex
* Scamalytics - Provides reputation about an IP via the scamalytics.com website
* Shodan - provides info about an IP in browser via Shodan itself.
* Spur.us - provides info about an IP in browser whether it is a VPN
* Threatminer - Returns reputation info about domain or IP address
* ThreatCrowd - Returns reputation info about domain or IP address
* URLHaus - Returns reputation info about domain or IP address
* URLscan.io - Run the URLScan.io to scan domain
* Virustotal - Perform Virustotal search within browser on IPs, domains
* WhoIs - Provide Whois info on domain/IP

## Usage

### Using ALL checks
To run all the checks on IPs/domains from file `assets.txt` listed below:- 
```
cat assets.txt | go run gogetassetinfo.go -md all -mi all
```

### Using AbuseIPDB 
The APIv2 of AbuseIP's API is used. This requires creation of an API account from https://www.abuseipdb.com/account/api and storing the API key in environment variable `ABUSEIP_API_KEY`. 

Then run the following command to get a summary of each IP from AbuseIP key
```
$ cat ips.txt | go run gogetassetinfo.go -mi abuseip
```

To get detailed info, use `-ar` flag for specific IP only. 
```
$ echo "1.1.1.1" | go run gogetassetinfo.go -mi abuseip -ar
```

### Using IPHub
For IPHub.io, an API key is required which can be either: -
* configured in the environment variable `IPHUB_KEY`, Or
* provided as an input argument `-ihk`

IPHub API can inform us whether an API is:
* block: 0 - Residential or business IP (i.e. safe IP)

* block: 1 - Non-residential IP (hosting provider, proxy, etc.)

* block: 2 - Non-residential & residential IP (warning, may flag innocent people)

To get information about given IPs in file `/tmp/ips.txt`:-
```
# Using env var
cat /tmp/ips.txt | go run gogetassetinfo.go -mi iphub | tee /tmp/results.txt

# Using IP Hub API Key in command line
cat /tmp/ips.txt | go run gogetassetinfo.go -mi iphub -ihk XYZ123 | tee /tmp/results.txt

```
More info about the API is available `here`: https://iphub.info/api

### Using whois
To get the WhoIs information about given domain/IP: -
```
echo -e "1.1.1.1\n2.2.2.2\ngoogle.com" | go run gogetassetinfo.go -md whois -mi whois | tee /tmp/results.txt
```

### Using whois to get organization's name
To get the organization's name for an IP or domain via WhoIs: -
```
$ cat assets.txt
1.1.1.1
google.com

$ cat assets.txt | go run gogetassetinfo.go -mi org_whois -md org_whois | tee /tmp/results.txt
```

### Using Alienvault
To get the Alienvault pulses and other info about the domain/IP :-
```
echo -e "1.1.1.1\n2.2.2.2" | go run gogetassetinfo.go -mi alienvault -md alienvault | tee /tmp/results.txt
```

### Using Scamalytics
To get the Scamalytics reputation info about the IP in default browser:-
```
echo -e "1.1.1.1\n2.2.2.2" | go run gogetassetinfo.go -mi scamalytics
```

### Using IPQualityScore.com
To get the IP reputation info via the IPQualityScore.com website :-
```
echo -e "1.1.1.1\n2.2.2.2" | go run gogetassetinfo.go  -mi ipqualityscore
```

### Using ipinfo.io
To get the info about the IP via ipinfo.io:-
```
echo -e "1.1.1.1\n2.2.2.2" | go run gogetassetinfo.go  -mi ipinfo.io
```

### Using DNS Resolutions 
To get the DNS resolutions for MX, DNS, A records for domains listed in file `domains.txt` : -
```
# A record
cat domains.txt | go run gogetassetinfo.go -md dnsa 
cat domains.txt | go run gogetassetinfo.go -md resolve 

# TXT record
cat domains.txt | go run gogetassetinfo.go -md dnstxt

# MX record
cat domains.txt | go run gogetassetinfo.go -md dnsmx 
```

For IP addresses, it is possible to get Reverse PTR record:
```
# PTR Records for IPs
cat ips.txt | go run gogetassetinfo.go -mi dnsptr
```

### Using Virustotal
To get the information about the domain OR IP via Virustotal in a browser, use 
the following command: -

```
# Virustotal for IP
cat ips.txt | go run gogetassetinfo.go -mi virustotal

# Virustotal for Domain
cat ips.txt | go run gogetassetinfo.go -md virustotal
```

### Performing Google VPN Check
To get an indication which VPN an IP may belong to, you can run the GoogleVPNCheck
module which will perform a search in browser to confirm whether an IP may be 
part of VPN.

```
# Google VPN Check for IP
cat ips.txt | go run gogetassetinfo.go -mi googlevpncheck
```

### Using Shodan
To get info about IP in Shodan.io

```
cat ips.txt | go run gogetassetinfo.go -mi shodan
```

### Open Phishtank website
To get info about domain via phishtank

```
cat subdomains.txt | go run gogetassetinfo.go -md phishtank
```

### Open URLScan.io website
To get info about domain via urlscan.io

```
cat subdomains.txt | go run gogetassetinfo.go -md urlscan.io
```

### Using Threatminer
To get info about domain via threatminer in a browser

```
cat ips-subdomains.txt | go run gogetassetinfo.go -mi threatminer -md threatminer
```

### Using Threatcrowd
To get info about an IP/domain via threatcrowd in a browser
```
cat ips-subdomains.txt | go run gogetassetinfo.go -mi threatcrowd -md threatcrowd
```

### Using Robtex
To get info about domain via robtex

```
$ cat ip-subdomains.txt
google.com
1.1.1.1

$ cat ips-subdomains.txt | go run gogetassetinfo.go -mi robtex -md robtex
```

### Using URLHaus 
To get the information about IP and domain name via URLHaus
```
$ cat ip-subdomains.txt
google.com
1.1.1.1

$ cat ip-subdomains.txt | go run gogetassetinfo.go -mi urlhaus -md urlhaus
```

### Using Spur.us 
To get the information about IP and domain name via spur.us
```
$ cat ip-subdomains.txt
google.com
1.1.1.1

$ cat ip-subdomains.txt | go run gogetassetinfo.go -mi spur.us -md urlhaus
```

### Using greynoise.io 
To get the information about scanning activity about an IP via greynoise.io
```
$ cat ip.txt
45.155.204.227

$ cat ip.txt | go run gogetassetinfo.go -mi greynoise
```

### TODO
- [ ] Add support for checking MD5/SHA256 hashes via various sources such as 
URLHaus, Virustotal

- [ ] Search for malware on malshare.com where malware can also be downloaded
```
https://malshare.com/search.php?query=0c3c45d8986dda1be12826bde2efd027
```

- [ ] Search for a hash in hybrid-analysis where payload can also be downloaded


#### URL

#### IP
- [ ] Add Kloth for IP abuse checks - MultiDNSBL-check: https://kloth.net/services/dnsbl.php