import time
import requests
import pandas as pd
import json
import os
from dotenv import load_dotenv
from datetime import datetime
import ipaddress
from termcolor import colored

# rewrite from Python Automated VT API v3 IP address and URL analysis 2.0 by Brett Fullam
# can get entire python files by $ git clone https://github.com/b-fullam/Automating-VirusTotal-APIv3-for-IPs-and-URLs.git


# ////////////////////////////////// START URL REPORT REQUEST

# this is the function that will take user input or input from a list to submit urls/ips to VirusTotal for url/ip reports, receive and format the returned json for generating our html reports
class virustotal_api:
    def __init__(self):
        # load_dotenv will look for a .env file and if it finds one it will load the environment variables from it
        load_dotenv()
        # retrieve API key from .env file and store in a variable
        self.API_KEY = os.getenv("vt_API_KEY")
        self.API_URL = None
        self.ip_df = None
        self.vt_dfs = []
        self.unable_check_ip = []
        self.malicious_ip = []
        self.private_ip = []
        
    def virustotal_Ip(self, Ip):
        print("\tworking on ---> {}".format(Ip))
        # amend the virustotal apiv3 url to include the unique generated url_id
        self.API_URL = "https://www.virustotal.com/api/v3/ip_addresses/" + Ip

        # while you can enter your API key directly for the "x-apikey" it's not recommended as a "best practice" and should be stored-accessed separately in a .env file (see comment under "load_dotenv()"" for more information
        headers = {
            "Accept": "application/json",
            "x-apikey": self.API_KEY
        }
        response = requests.get(self.API_URL, headers=headers).json()
        data_key = "data"
        if response.get(data_key):
            data = response["data"]["attributes"]
        else:
            print(f"Unable to check ip {Ip}")
            self.unable_check_ip.append(Ip)
            return None
        
        # simplify last_analysis_stats attribute in order to further usage
        # get malicious detection
        last_analysis_malicious = data['last_analysis_stats']['malicious']
        last_analysis_all = sum(data['last_analysis_stats'].values())
        if last_analysis_malicious > 0:
            self.malicious_ip.append(Ip)
            print(colored(f"\t{Ip}: {last_analysis_malicious}/{last_analysis_all}", "red"))

        data["security vendors' analysis"] = f'{last_analysis_malicious}/{last_analysis_all}'
        data['ip'] = Ip

        # create a dataframe with the remaining keys stored in the filteredResponse dictionary
        # orient="index" is necessary in order to list the index of attribute keys as rows and not as columns
        df = pd.DataFrame([data])
        df = df.set_index('ip', drop=False)

        return df

    def multiple_ip_check(self, ips):
        print("working on ---> virustotal ip check")
        # ip must in list
        for ip in set(ips):
            if ipaddress.ip_address(ip).is_private == True:
                self.private_ip.append(ip)
                continue
            elif ip in self.unable_check_ip:
                continue
            else:
                vt_df = self.virustotal_Ip(ip)
                self.vt_dfs.append(vt_df)
        self.ip_df = pd.concat(self.vt_dfs)
        self.ip_df = self.ip_df.set_index("ip")
        
        return self.ip_df


# ////////////////////////////////// END URL REPORT REQUEST

# print(virustotal_Ip('8.8.8.8').T)

