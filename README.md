# gogetassetinfo
Golang script that acts as a wrapper to get Reputation/information about domains/IP addresses through various methods.

Currently, results are printed directly to the output, and the raw results are displayed to the output.

## Setup
To install the script in `$GOPATH`, simply run:
```
go get -u github.com/manasmbellani/gogetassetinfo
```

## Supported API Sources
* IPHub.info - API which provides IP types (residential/proxy) for various ip addresses
* WhoIs - Provide Whois info on domain/IP
* Alienvault - Provide Alienvault pulse info in raw format.
* ipinfo.io - Provides info about an IP via `https://ipinfo.io`
* Scamalytics - Provides reputation about an IP via the scamalytics.com website
* IPQualityScore.com - provides reputation about an IP via the ipqualityscore.com website
* DNS Resolutions - provide DNS A, TXT, MX DNS resolution for domains

## Usage

### Using ALL checks
To run all the checks on IPs/domains from file `assets.txt` listed below:- 
```
cat assets.txt | go run gogetassetinfo.go -md all -mi all
```

### Using IPHub
For IPHub.io, an API key is required which can be either: -
* configured in the environment variable `IPHUB_KEY`, Or
* provided as an input argument `-ihk`

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
echo -e "1.1.1.1\n2.2.2.2\ngoogle.com" | go run gogetassetinfo.go  -md whois -mi whois | tee /tmp/results.txt
```

### Using Alienvault
To get the Alienvault pulses and other info about the domain/IP :-
```
echo -e "1.1.1.1\n2.2.2.2" | go run gogetassetinfo.go  -mi alienvault -md alienvault | tee /tmp/results.txt
```

### Using Scamalytics
To get the Scamalytics reputation info about the IP in default browser:-
```
echo -e "1.1.1.1\n2.2.2.2" | go run gogetassetinfo.go  -mi scamalytics
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
To get the DNS resolutions for MX, DNS, A records for domains listed in file `domains.txt`
```
# A record
cat domains.txt | go run gogetassetinfo.go -md dnsa 

# TXT record
cat domains.txt | go run gogetassetinfo.go -md dnstxt

# MX record
cat domains.txt | go run gogetassetinfo.go -md dnsmx 
```

### TODO:
#### URL
* Check Phishtank status for a URL
* Get ALL URL redirections
* Get response headers in the URL
* Get Virustotal IOC for a URL

#### Domain 
* Get Virustotal IOC for a domain

#### IP
* Open IP in Shodan
