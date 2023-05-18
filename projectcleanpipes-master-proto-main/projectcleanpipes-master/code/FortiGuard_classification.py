# Feature / code deprecated, will keep in file for frame of refence

import urllib
import re
import pandas as pd
import tld
import itertools
import sqlite3
import ast

def extract_urls(raw_urls):
    raw_urls = ast.literal_eval(raw_urls)
    urls = []
    if (len(raw_urls) == 0):
        return []
    for item in raw_urls:
        urls.append(item['expanded_url'])
    return urls

def map_url_to_domain(expanded_urls):
    domains = []
    for url in expanded_urls:
        try:
            domain = tld.get_fld(url.strip()).strip()
            domains.append(domain)
        except:
            continue
    return domains

class Fortiguard:

    def check_category(self, domain):
        print("[*] Checking category for " + domain)
        request = urllib.request.Request("https://web.archive.org/web/20220826091730/https://www.fortiguard.com/webfilter?q=" + domain)
        request.add_header("User-Agent", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)")
        request.add_header("Origin", "https://fortiguard.com")
        request.add_header("Referer", "https://fortiguard.com/webfilter")
        try:
            response = urllib.request.urlopen(request, timeout=10)
            resp = response.read().decode('utf-8')
            cat = re.findall('Category: (.*?)" />', resp, re.DOTALL)
            # print("\033[1;32m[!] Site categorized as: " + cat[0] + "\033[0;0m")
            return cat[0]
        except Exception as e:
            # print("[-] An error occurred")
            # print(e)
            pass

if __name__ == "__main__":
    conn = sqlite3.connect('./fortiguard_scan_report_.db')
    cc = conn.cursor()
    try:
        cc.execute('''CREATE TABLE domain_category (domain, category TEXT)''') 
    except:
        pass
    domains = [x.strip() for x in open("data\CopyRight_Telstra.txt").readlines()]
    
    print('Total unique domains = ', len(domains))
    b = Fortiguard()
    for domain in domains:
        try:
            cat = b.check_category(domain)
        except:
            cat = 'N/A'
        # store to db
        try:
            cc.execute("INSERT INTO domain_category VALUES (?,?)", (domain, cat)) 
            conn.commit()
        except:
            pass
    print('Done categorization')
    cc.close()