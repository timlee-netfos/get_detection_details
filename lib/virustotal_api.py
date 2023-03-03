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
        self.API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
        self.data = []
        self.malicious_ip = []
        self.private_ip = []
        self.load_vt_API_KEY()
    
    def load_vt_API_KEY(self):
        load_dotenv()
        try_times = 3
        while try_times > 0:
            if os.getenv("vt_API_KEY") == None:
                print(colored("[新增 virustotal API KEY]", "green"))
                self.API_KEY = input("請輸入 virustotal API KEY: ")
                headers = {
                    "Accept": "application/json",
                    "x-apikey": self.API_KEY
                }
                r = requests.get(self.API_URL+"8.8.8.8", headers=headers).status_code
                if r >= 200 and r < 300:
                    with open("lib/.env", "a") as fa:
                        fa.write(f"\nvt_API_KEY={self.API_KEY}")
                    print(colored("新增 virustotal API KEY 成功!", "green"))
                    return None
                else:
                    print(f"HTTP status code:", colored(r, "yellow"))
                    print(colored("輸入錯誤，請重新輸入", "red"))
                    try_times -= 1
                    continue
            else:
                self.API_KEY = os.getenv("vt_API_KEY")
                return None
        print(colored("錯誤次數已達 3 次，程式終止", "yellow"))
        exit(1)

    def virustotal_Ip(self, Ip):
        # amend the virustotal apiv3 url to include the unique generated url_id
        URL = self.API_URL + Ip

        # while you can enter your API key directly for the "x-apikey" it's not recommended as a "best practice" and should be stored-accessed separately in a .env file (see comment under "load_dotenv()"" for more information
        headers = {
            "Accept": "application/json",
            "x-apikey": self.API_KEY
        }
        response = requests.get(URL, headers=headers).json()
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

        self.data.append(data)

        return None

    def multiple_ip_check(self, ips):
        print("working on ---> virustotal ip check")
        with open("data/unable_check_ip.txt", "r") as fr:
            self.unable_check_ip = fr.read().split("\n")
        # ip must in list
        for ip in set(ips):
            if ipaddress.ip_address(ip).is_private == True:
                self.private_ip.append(ip)
                continue
            else:
                self.virustotal_Ip(ip)
        self.ip_df = pd.DataFrame(self.data)

        with open("data/unable_chekc_ip.txt", "w") as fw:
            fw.write("\n".join(self.unable_check_ip))

        print("done!")
        print(f"private ip:" + "\n".join(self.private_ip))
        print(colored("\n[MALICIOUS IP]\n", "red") + "\n".join(self.malicious_ip))
        print(colored("[UNABLE TO ANALYZE]\n", "yellow") + "\n".join(self.unable_check_ip))

        # use cache?
        # use other data structure?

        return None

# ////////////////////////////////// END URL REPORT REQUEST

# print(virustotal_Ip('8.8.8.8').T)

