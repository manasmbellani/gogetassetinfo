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

## Usage

### Using IPHub
To get information about given IP, run following command: 
```
cat /tmp/ips.txt | go run gogetassetinfo.go -mi iphub
```
