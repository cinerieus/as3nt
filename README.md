![Version 1.0.5](http://img.shields.io/badge/version-v1.0.4-purple.svg)
![Python 3.8](http://img.shields.io/badge/python-3.8-yellow.svg)
[![GPL License](http://img.shields.io/badge/license-GPL%20License-blue.svg)](https://github.com/cinerieus/as3nt/blob/master/LICENSE)  

## As3nt
Another Subdomain ENumeration Tool - written in python to enumerate and enrich subdomains using passive OSINT.  

As3nt can target TLDs or subdomains. The enumeration uses; VirusTotal, HackerTarget, ThreatCrowd, ThreatMiner, BufferOver, urlscan.io and crt.sh. Each subdomain IP is resolved using public DNS servers and the data is enriched using ipwhois and Shodan. As3nt currently outputs to terminal or csv. 

Along with using the tags from Shodan, this tool also adds it's own tags. Currently there are tags added based on certain HTML content found by Shodan like tomcat, fortinet, netscaler and pulse vpn. Also if any CVEs are found for an IP/Subdomain with a CVSS score >= 7.8, these assets are tagged to highlight a possible exploit. 

## Screenshots 
![As3nt_1](https://github.com/cinerieus/as3nt/blob/master/screenshots/as3nt_1.gif)  
![As3nt_2](https://github.com/cinerieus/as3nt/blob/master/screenshots/as3nt_2.gif)

## Installation 
1. Install:
  - with pip: `pip install as3nt`
  - from git (source): 
	- `git clone https://github.com/cinerieus/as3nt.git && cd as3nt/`  
	- `pip install -r requirements.txt`
	- `python ./as3nt/core.py` 
  - from git (releases):
	- `wget https://github.com/cinerieus/as3nt/archive/v1.0.5.tar.gz`
	- `pip install v1.0.5.tar.gz` 
2. Remember to check PATH if you installed in ~/.local/bin/ 
3. Profit! 

*For Shodan functionality set the environment variable 'SHODANKEY' with your API key. 

## Dependencies 
See [requirements.txt](https://github.com/cinerieus/as3nt/blob/master/requirements.txt) 

## Changelog
See [CHANGELOG.md](https://github.com/cinerieus/as3nt/blob/master/CHANGELOG.md) 

## Usage 
![usage](https://github.com/cinerieus/as3nt/blob/master/screenshots/usage.png)  
*If selected Shodan is rate-limited to 1 IP per second.

#### Examples:  
- Run all modules against 'example.com' and save results to csv:  
`as3nt -t example.com -11 -o results.csv`   
- Run against a subdomain:  
`as3nt -s -t subdomain.example.com -11 -o results.csv`  

## Thanks  
- Thanks to [aboul3la](https://github.com/aboul3la/) for the inspiration from [sublist3r](https://github.com/aboul3la/Sublist3r)
