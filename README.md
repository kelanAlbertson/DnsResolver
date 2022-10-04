# DnsResolver
### Created by Kelan Albertson
### February 10, 2022

> This is a simple caching DNS resolver. It listens for DNS requests on port 8053 and checks its cache for a valid response or forwards the request to Google's DNS server at 8.8.8.8 and updates its cache with the response. This DNS resolver is only capable of basic lookup queries.

## How to Use:

1. Download the files from this repo
2. Run the program from the DNSServer.java file
3. From the command line use the dig command to create a DNS lookup query for any url (valid or invalid) such as the one below:
```dig example.com @127.0.0.1 -p 8053```