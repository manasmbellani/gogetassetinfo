# gogetassetinfo
Golang script that acts as a wrapper to get Reputation/information about domains/IP addresses through various methods.

Currently, results are printed directly to the output.

## Setup
To install the script in `$GOPATH`, simply run:
```
go install gogetassetinfo.go
```

## Supported API Sources
* IPHub.info - API which provides IP types (residential/proxy) for various ip addresses
* WhoIs - Provide Whois information on domain/IP

## Usage

### Using IPHub
To get information about given IPs in file `/tmp/ips.txt`, simply run following command:-
```
cat /tmp/ips.txt | go run gogetassetinfo.go -mi iphub | tee /tmp/results.txt
```
More info about the API is available `here`: https://iphub.info/api

### Using whois
To get the WhoIs information about given domain/IP: -
```
echo -e "1.1.1.1\n2.2.2.2" | go run gogetassetinfo.go  -mi whois | tee /tmp/results.txt
```

### Using Alienvault
To get the Alienvault pulses and other info about the domain/IP :-
```
echo -e "1.1.1.1\n2.2.2.2" | go run gogetassetinfo.go  -mi alienvault -md alienvault | tee /tmp/results.txt
```