#########################################
# Name: as3nt
# Author: cinerieus
# Description: Main script for As3nt
##########################################

import os
import sys
import csv
import time
import ipwhois
import argparse
import dns.resolver
from tqdm import tqdm
from shodan import Shodan
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor

try:
    from as3nt.subenum import SubEnum
except:
    from subenum import SubEnum

class As3nt:
    #class initialisation, declares instance variables and calls main()
    def __init__(self,target,threads,asn,shodan,output,shodankey,subdomains,subonly):
        self.datadict = {}
        self.target = target
        self.threads = threads
        self.asn = asn
        self.shodan = shodan
        self.output = output
        self.shodankey = shodankey
        self.subdomains = subdomains
        self.subonly = subonly

    def run(self):
        try:
            #subdomain input check
            if not self.subdomains:
                subenum = SubEnum(self.target)
                sublist = subenum.main()
                if not sublist:
                    print(colored('No subdomains for: '+self.target+'\n', 'green'))
                    return
                if self.subonly:
                    if self.output:
                        with open(self.output, 'w') as f:
                            for s in sublist:
                                f.write(s+'\n')
                        print(colored('Results saved to: '+self.output+'\n', 'green'))
                    return
            else:
                sublist = self.target
                self.target = 'N/A'
            #threading for i/o heavy tasks, fetches dns records and asn data for each asset
            with ThreadPoolExecutor(max_workers=int(self.threads)) as pool:
                print(colored('\nGetting DNS records...', 'magenta'))
                list(tqdm(pool.map(self.getrecords, sublist), total=len(sublist)))
                if self.asn:
                    print(colored('\nGetting ASN data...', 'magenta'))
                    aslist = list(self.datadict.values())
                    list(tqdm(pool.map(self.getasn, aslist), total=len(aslist)))
            #shodan option check, limited to 1 ip per second by api
            if self.shodan:
                api = Shodan(self.shodankey)
                print(colored('\nGetting Shodan data...', 'magenta'))
                for asset in tqdm(self.datadict.values()):
                    self.getshodan(api,asset)
                    time.sleep(1)
            #output option check, writes to csv also checks for existing file to prevent duplicating header
            if self.output:
                dictlist = list(self.datadict.values())
                keylist = [list(x.keys()) for x in dictlist]
                header = max(keylist, key=len)
                if not os.path.isfile(self.output):
                    with open(self.output, 'w') as f:
                        w = csv.DictWriter(f, header, extrasaction='ignore')
                        #w = csv.DictWriter(f, dictlist[header].keys())
                        w.writeheader()
                        w.writerows(dictlist)
                    print(colored('Results saved to: '+self.output, 'green'))
                else:
                    with open(self.output, 'a') as f:
                        w = csv.DictWriter(f, header, extrasaction='ignore')
                        #w = csv.DictWriter(f, dictlist[header].keys())
                        w.writerows(dictlist)
                    print(colored('Results saved to: '+self.output, 'green'))
            else:
                dictlist = list(self.datadict.values())
                for item in dictlist:
                    print(item)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print('\nError in run:')
            print(e)
            sys.exit(2)

    def getrecords(self,subdomain):
        #handles getting the records for each subdomain, dns server(s) is specified below
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ['1.1.1.1', '1.0.0.1']
            resolver.timeout = 3
            resolver.lifetime = 3
            #gets A records and starts populating main dict, drops CNAME
            try: 
                A = resolver.resolve(subdomain, 'A')
                for rec in A.response.answer:
                    if 'CNAME' not in rec.to_text():
                        for x in rec.items:
                            self.datadict[subdomain+x.to_text()] = {'tld':self.target, 'subdomain':subdomain, 'record':'A', 'ip':x.to_text()}
            except:
                pass
            #gets AAAA records, drops CNAME
            try: 
                AAAA = resolver.resolve(subdomain, 'AAAA')
                for rec in AAAA.response.answer:
                    if 'CNAME' not in rec.to_text():
                        for x in rec.items:
                            self.datadict[subdomain+x.to_text()] = {'tld':self.target, 'subdomain':subdomain, 'record':'AAAA', 'ip':x.to_text()}
            except:
                pass
            #gets MX records, note these are also a subdomain rather than IP.
            try: 
                MX = resolver.resolve(subdomain, 'MX')
                for rec in MX.response.answer:

                    for x in rec.items:
                        self.datadict[subdomain+x.to_text()] = {'tld':self.target, 'subdomain':subdomain, 'record':'MX', 'ip':x.to_text().split(' ')[1]}
            except:
                pass
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print('\nError in getrecords:')
            print(e)
            sys.exit(2)
    
    def getasn(self,asset):
        #gets ASN data using ipwhois module and RDAP lookup
        try:
            whois = ipwhois.IPWhois(asset['ip'])
            asdata = whois.lookup_rdap(depth=1, retry_count=3, rate_limit_timeout=1, asn_methods=['dns', 'whois', 'http'])
            asn = asdata['asn']
            asndesc = asdata['asn_description']
            try:
                name = asdata['network']['name']
                cidr = asdata['network']['cidr']
            except:
                try:
                    name = asdata['nets'][len(asdata['nets']-1)]['name']
                    cidr = asdata['nets'][len(asdata['nets']-1)]['cidr']
                except:
                    name = 'Not Found'
                    cidr = asdata['adn_cidr']
                    pass
                pass
            self.datadict[asset['subdomain']+asset['ip']].update({'asn':asn, 'asn_description':asndesc, 'asn_netblock':cidr, 'asn_netname':name}) 
        except KeyboardInterrupt:
            raise
        except Exception as e:
            #print('\nError in getasn:')
            #print(e)
            #sys.exit(2)
            pass

    def getshodan(self,api,asset):
        #get Shodan data per IP, rate limited to 1 per second
        try:
            try:
                # strings to check for in html grabbed by shodan
                taglist = [
                        'tomcat',
                        'fortinet',
                        'netscaler',
                        'pulse connect'
                        ]

                results = api.host(asset['ip'])
                ports = sorted(results['ports'])
                isp = results['isp']
                org = results['org']
                country = results['country_code']
                try:
                    tags = results['tags']
                except:
                    tags = []
                    pass
                try:
                    OS = results['os']
                except:
                    OS = ''
                    pass
                try:
                    vulns = results['vulns']
                except:
                    vulns = []
                    pass

                # loops over shodan data to get html and CVE scores
                for i in range(len(results['data'])):
                    # checks html content for strings is taglist and appends to tags
                    if results['data'][i].get('http'):
                        try:
                            html = results['data'][i]['http']['html'].lower()
                            for t in taglist:
                                if t in html and t not in tags:
                                    tags.append(t)
                        except:
                            pass
                    # checks CVE's for cvss score, if it's "10" tag as possible exploit
                    if results['data'][i].get('vulns'):
                        for r in results['data'][i]['vulns'].values():
                            try:
                                cvss = r['cvss']
                                if cvss >= 7.8:
                                    if 'possible_exploit!' not in tags:
                                        tags.append('possible_exploit!')
                                        break
                            except:
                                pass
            except Exception as e:
                ports = ''
                tags = ''
                isp = ''
                org = ''
                country = ''
                OS = ''
                vulns = ''
                pass
            self.datadict[asset['subdomain']+asset['ip']].update({'shodan_os':OS, 'shodan_tags':tags, 'shodan_ports':ports, 'shodan_vulns':vulns, 'shodan_isp':isp, 'shodan_org':org, 'shodan_country':country})
        except KeyboardInterrupt:
            raise
        except Exception as e:
            #print('\nError in getshodan:')
            #print(e)
            #sys.exit(2)
            pass
def main():
    # argument declaration
    parser = argparse.ArgumentParser(description='Another Subdomain ENumeration Tool', usage='as3nt -t example.com -11 -o results.csv')
    parser._action_groups.pop()
    required = parser.add_argument_group('Required arguments (-t or -f)')
    optional = parser.add_argument_group('Optional arguments')
    required.add_argument('-t', action='store', dest='target', help='A target TLD or subdomain.')
    required.add_argument('-f', action='store', dest='targetfile', help='A target file that contains a list of TLDs or subdomains.')
    required.add_argument('-o', action='store', dest='output', help='Outputs to a csv.')
    optional.add_argument('-s', action='store_true', dest='subdomains', help='Use for inputing a list of subdomains.')
    optional.add_argument('-so', action='store_true', dest='subonly', help='If specified, will only perform subdomain enumeration.')
    optional.add_argument('-td', action='store', dest='threads', help='Specify number of threads used (defaults to 40).', default=40)
    optional.add_argument('-11', action='store_true', dest='eleven', help='Choose this option to enable all modules.')
    optional.add_argument('-as', action='store_true', dest='asn', help='This option enables the ASN data module.')
    optional.add_argument('-sh', action='store_true', dest='shodan', help='This option enables the Shodan data module.')
    args = parser.parse_args()

    # banner
    print(colored("""
                  ____        _
        /\       |___ \      | |
       /  \   ___  __) |_ __ | |_
      / /\ \ / __||__ <| '_ \| __|
     / ____ \\\__ \___) | | | | |_
    /_/    \_\___/____/|_| |_|\__|
    """, 'magenta'))
    print(colored("""
        Written by - @cinereus
    """, 'yellow'))
    print(colored("""
   Another Subdomain ENumeration Tool
    """, 'cyan'))

    # checks for empty/incompatible args
    if not args.target and not args.targetfile or args.target and args.targetfile:
        #parser.print_help()
        print(colored("""
usage: as3nt -t example.com -11 -o results.csv

Required arguments (-t or -f):
-t TARGET      A target TLD or subdomain.
-f TARGETFILE  A target file that contains a list of TLDs or subdomains.
-o OUTPUT      Outputs to a csv.

Optional arguments:
-s             Use for inputing a list of subdomains.
-so            If specified, will only perform subdomain enumeration.
-td THREADS    Specify number of threads used (defaults to 40).
-11            Choose this option to enable all modules.
-as            This option enables the ASN data module.
-sh            This option enables the Shodan data module.
        """, 'green'))
        print('\n')
        sys.exit(0)

    #check for 11 option
    if args.eleven:
        args.asn = True
        args.shodan = True

    # format input
    if args.target:
        target = [args.target]
    else:
        target = []
        with open(args.targetfile, 'r') as csvin:
            reader = csv.reader(csvin)
            rawlist = list(reader)
            for x in rawlist:
                target.append(x[0])

    #shodan api key check
    try:
        shodankey = os.environ['SHODANKEY']
        if shodankey == '':
            print('\nShodan API key not set, disabling Shodan module...\n')
            args.shodan = False
    except:
        print('\nShodan API key not set, disabling Shodan module...\n')
        shodankey = ''
        args.shodan = False
        pass

    #checks for list of subdomains or tlds
    if not args.subdomains:
        try:
            for t in target:
                as3nt =  As3nt(t,args.threads,args.asn,args.shodan,args.output,shodankey,args.subdomains,args.subonly)
                as3nt.run()
                print('\n')
        except KeyboardInterrupt:
            print(colored('Exiting...', 'red'))
            exit(0)
        except Exception as e:
            print('\nError in main:')
            print(e)
            sys.exit(1)
    else:
        try:
            as3nt = As3nt(target,args.threads,args.asn,args.shodan,args.output,shodankey,args.subdomains,args.subonly) 
            as3nt.run()
        except KeyboardInterrupt:
            print(colored('Exiting...', 'red'))
            exit(0)
        except Exception as e:
            print('\nError in main:')
            print(e)
            sys.exit(1)

if __name__ == '__main__':
    main()
