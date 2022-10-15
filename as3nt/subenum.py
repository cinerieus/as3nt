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
                self.ThreatMiner,
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
                if 'data' in jsondata.keys():
                    for x in jsondata['data']:
                        self.sublist.append(x['id'])
                    if 'next' in jsondata['links']:
                        urls.append(jsondata['links']['next'])
        except KeyboardInterrupt:
            raise
        except:
            print(colored('[-] VirusTotal - Hit rate limiting!', 'red'))
    
    # HackerTarget feed
    def HackerTarget(self):
        try:
            get = requests.get('https://api.hackertarget.com/hostsearch/?q='+self.tld)
            if get.text == 'API count exceeded - Increase Quota with Membership':
                print(colored('[-] HackerTarget - API quota exceeded!', 'red'))       
            elif get.text != 'error check your search parameter':
                result = get.text.split('\n')
                for r in result:
                    self.sublist.append(r.split(',')[0])
        except KeyboardInterrupt:
            raise
        except:
            print(colored('[-] HackerTarget - Error in response!', 'red'))       

    # ThreatMiner feed
    def ThreatMiner(self):
        try:
            get = requests.get('https://api.threatminer.org/v2/domain.php?q='+self.tld+'&rt=5')
            result = json.loads(get.text)
            if result['status_code'] != '404':
                self.sublist.extend(result['results'])
        except KeyboardInterrupt:
            raise
        except:
            print(colored('[-] ThreatMiner - Error in response!', 'red'))       
    
    # urlscan.io feed
    def urlscan_io(self):
        try:
            get = requests.get('https://urlscan.io/api/v1/search/?q=domain:'+self.tld)
            result = json.loads(get.text)
            if result['total'] != '0':
                for r in result['results']:
                    self.sublist.append(r['page']['domain'])
        except KeyboardInterrupt:            
            raise
        except:
            print(colored('[-] urlscan.io - Error in response!', 'red'))

    # crt.sh feed
    def crt_sh(self):
        try:
            get = requests.get('https://crt.sh/?q=.'+self.tld+'&output=json')
            if get.status_code == 200:
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
        except KeyboardInterrupt:
            raise
        except:
            print(colored('[-] crt.sh - Error in response!', 'red'))

# check if being used as module, allows being run standalone
if __name__ == '__main__':
    subenum = SubEnum(sys.argv[1])
    subenum.main()
