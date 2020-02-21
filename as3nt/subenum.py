#####################################################
# Name: subenum
# Author: cinerieus
# Description: Subdomain enumeration module for As3nt 
#####################################################

import sys
import json
import requests
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor

class SubEnum:
    # class init, defines class variables
    def __init__(self,tld):
        self.sublist = []
        self.tld = tld
        # sources defined here, they can be excluded by commenting out
        self.sources = [
                self.VirusTotal,
                self.HackerTarget, 
                self.ThreatCrowd,
                self.ThreatMiner,
                self.BufferOver,
                self.urlscan_io,
                self.crt_sh
                ]

    def main(self):
        print(colored('Starting subdomain enumeration for '+self.tld+'...', 'magenta'))
        
        # define thread pool with maximum of 20 threads
        with ThreadPoolExecutor(max_workers=20) as pool:
            # tasks is defined here to allow thread tracking for progress check
            tasks = {}
            # loops over source list and submits a task to the thread pool for each source
            for s in self.sources:
                source = s.__name__
                print(colored('[+] '+source, 'cyan'))
                tasks[source] = (pool.submit(s))
            # submits a task to the thread pool for each existsing task, this is used to track the progress or the enumeration
            pool.map(self.progress, tasks.items())

        result = self.inscope(list(set(self.sublist)))
        print(colored('\nTotal: '+str(len(result)), 'yellow'))
       
        # run as module check, allows being run standalone
        if __name__ == '__main__':
            fn = self.tld.replace('.','')+'.txt'
            with open(fn, 'w') as f:
                for r in sorted(result):
                    f.write(r+'\n')
            print(colored('Results saved to: '+fn, 'green'))
        else:
            return sorted(result)

    # progress check for enum progress
    def progress(self,tasks):
        while tasks[1].done() == False:
            pass
        print(colored('[-] '+tasks[0]+' done.', 'green'))
    
    # check if returned subdomains are in the scope of the target
    def inscope(self,sublist):
        for i,v in enumerate(sublist):
            if self.tld not in v:
                del sublist[i]
        return sublist
    
    # VirusTotal feed
    def VirusTotal(self):
        try:
            urls = ['https://www.virustotal.com/ui/domains/'+self.tld+'/subdomains?limit=40']
            for url in urls:
                get = requests.get(url)
                jsondata = json.loads(get.text)
                for x in jsondata['data']:
                    self.sublist.append(x['id'])
                if 'next' in jsondata['links']:
                    urls.append(jsondata['links']['next'])
        except Exception as e:
            #print('Error in subenum.VirusTotal:')
            #print(e)
            #sys.exit(2)
            print(colored('[-] VirusTotal - Hit rate limiting!', 'red'))
            pass
    
    # HackerTarget feed
    def HackerTarget(self):
        try:
            get = requests.get('https://api.hackertarget.com/hostsearch/?q=.'+self.tld)
            if get.text == 'API count exceeded - Increase Quota with Membership':
                print(colored('[-] HackerTarget - API quota exceeded!', 'red'))       
            elif get.text != 'error check your search parameter':
                result = get.text.split('\n')
                for r in result:
                    self.sublist.append(r.split(',')[0])
        except Exception as e:
            print('Error in HackerTarget:')
            print(e)
            sys.exit(2)
    
    # ThreatCrowd feed
    def ThreatCrowd(self):
        try:
            get = requests.get('https://www.threatcrowd.org/searchApi/v2/domain/report/?domain='+self.tld)
            result = json.loads(get.text)
            if result['response_code'] != '0':
                self.sublist.extend(result['subdomains'])
        except Exception as e:
            print('Error in ThreatCrowd:')
            print(e)
            sys.exit(2)

    # ThreatMiner feed
    def ThreatMiner(self):
        try:
            get = requests.get('https://api.threatminer.org/v2/domain.php?q='+self.tld+'&rt=5')
            result = json.loads(get.text)
            if result['status_code'] != '404':
                self.sublist.extend(result['results'])
        except Exception as e:
            print('Error in ThreatMiner:')
            print(e)
            sys.exit(2)
    
    # BufferOver feed
    def BufferOver(self):
        try:
            mlist = []
            get = requests.get('https://dns.bufferover.run/dns?q=.'+self.tld)
            result = json.loads(get.text)
            if result['FDNS_A']:
                mlist.extend(result['FDNS_A'])
            if result['RDNS']:
                mlist.extend(result['RDNS'])
            for i in mlist:
                self.sublist.append(i.split(',')[1])
        except Exception as e:
            print('Error in BufferOver:')
            print(e)
            sys.exit(2)
    
    # urlscan.io feed
    def urlscan_io(self):
        try:
            get = requests.get('https://urlscan.io/api/v1/search/?q=domain:'+self.tld)
            result = json.loads(get.text)
            if result['total'] != '0':
                for r in result['results']:
                    self.sublist.append(r['page']['domain'])
        except Exception as e:
            print('Error in urlscan_io:')
            print(e)
            sys.exit(2)

    # crt.sh feed
    def crt_sh(self):
        try:
            get = requests.get('https://crt.sh/?q=.'+self.tld+'&output=json')
            result = json.loads(get.text)
            if len(result) != 0:
                for r in result:
                    if '\n' in r['name_value']:
                        subs = r['name_value'].split('\n')
                    else:
                        subs = [r['name_value']]
                    for s in subs:
                        if '*' not in s:
                            self.sublist.append(s)
        except Exception as e:
            print('Error in crt_sh:')
            print(e)
            sys.exit(2)

# check if being used as module, allows being run standalone
if __name__ == '__main__':
    subenum = SubEnum(sys.argv[1])
    subenum.main()
