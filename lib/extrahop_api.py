# rewrite from ExtraHop code-example
# https://github.com/ExtraHop/code-examples/tree/main/py_rx360_auth
# License: https://github.com/ExtraHop/code-examples/blob/main/LICENSE

import requests
import base64
from dotenv import load_dotenv
import os
from termcolor import colored
from requests.exceptions import MissingSchema
from datetime import datetime
import re
import json

class ExtrahopApi:
    def __init__(self):
        # load confidential information from lib/.env
        load_dotenv()
        self.check_env()
        self.token = None
    
    def check_env(self):
        if not os.path.isfile("lib/.env"):
            self.vt_API_KEY()
            self.new_customer()
        else:
            self.load_customer()
            self.load_config()

    def load_customer(self):
        with open("data/customers.txt", "r") as fr:
            customers = fr.read().strip("\n")
        while True:
            self.customer = input("請輸入客戶名稱: ")
            if self.customer not in customers:
                check_wrong_customer = input(f"目前不存在客戶名稱 " + colored(f"{self.customer}", "blue") + "\n1. 新增客戶 2. 重新輸入: ")
                if check_wrong_customer == "1":
                    self.new_customer()
                    break
            else: 
                break

    def new_customer(self):
        try_times = 3
        while try_times > 0:
            print(colored("[新增客戶]", "green"))
            self.customer = input("請輸入客戶名稱: ")
            self.HOST = input("請輸入 API Endpoint: ")
            self.ID = input("請輸入 ID: ")
            self.SECRET = input("請輸入 SECRET: ")
            try:
                # self.get_info("apikeys")
                self.get_token()
            # except AttributeError:
            except (ConnectionError, KeyError, MissingSchema):
                if try_times > 1:
                    print(colored("輸入錯誤，請重新輸入", "red"))
                    try_times -= 1
                    continue
                else:
                    print(colored("錯誤次數已達 3 次，程式終止", "yellow"))
                    exit(1)
            with open("lib/.env", "a") as fa:
                fa.write(f"\n{self.customer}_HOST={self.HOST}\n{self.customer}_ID={self.ID}\n{self.customer}_SECRET={self.SECRET}")
            with open("data/customers.txt", "a") as fa:
                fa.write(f"\n{self.customer}")
            print(colored("新增客戶成功!", "green"))
            return None
            
        

    def vt_API_KEY(self):
        try_times = 3
        while try_times > 0:
            print(colored("[新增 virustotal API KEY]", "green"))
            vt_API_KEY = input("請輸入 virustotal API KEY: ")
            headers = {
                "Accept": "application/json",
                "x-apikey": vt_API_KEY
            }
            r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", headers=headers).status_code
            if r >= 200 and r < 300:
                load_dotenv()
                with open("lib/.env", "a") as fa:
                    fa.write(f"\nvt_API_KEY={vt_API_KEY}")
                print(colored("新增 virustotal API KEY 成功!", "green"))
                return None
            else:
                print(colored("輸入錯誤，請重新輸入", "red"))
                try_times -= 1
                continue
        print(colored("錯誤次數已達 3 次，程式終止", "yellow"))
        exit(1)
            
    

    def load_config(self):
        self.HOST = os.getenv(f"{self.customer}_HOST")
        self.ID = os.getenv(f"{self.customer}_ID")
        self.SECRET = os.getenv(f"{self.customer}_SECRET")            
    
    def get_token(self):
        # get token to access ExtraHop REST API
        auth = base64.b64encode(bytes(self.ID + ":" + self.SECRET, "utf-8")).decode("utf-8")
        headers = {
            "Authorization": "Basic " + auth,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        url = self.HOST + "/oauth2/token"
        r = requests.post(
            url, headers=headers, data="grant_type=client_credentials",
        )
        self.token = r.json()["access_token"]
        return self.token
    
    def get_info(self, page):
        # use GET method to get data
        headers = {"Authorization": "Bearer " + self.token}
        url = self.HOST + "/api/v1" + f"/{page}"
        r = requests.get(url, headers=headers)
        return r
    
    def post_info(self, page, payload):
        # use POST method to get data
        headers = {"Authorization": "Bearer " + self.token}
        url = self.HOST + "/api/v1" + f"/{page}"
        r = requests.post(url, headers=headers, json=payload)
        return r

class detection_details(ExtrahopApi):
    def __init__(self):
        super().__init__()
        self.start_time = None
        self.end_time = None
    def get_start_time(self):
        self.start_time = input("請輸入開始時間(yyyymmdd): ")
        pattern = r'^\d{8}$'
        while True:
            if re.match(pattern, self.start_time):
                try:
                    datetime.strptime(self.start_time, '%Y%m%d')
                    break
                except ValueError:
                    self.start_time = input(colored("日期錯誤，請輸入日期格式 yyyymmdd: ", "yellow"))
            else:
                self.start_time = input(colored("日期錯誤，請輸入日期格式 yyyymmdd: ", "yellow"))
        return self.start_time

    def get_end_time(self):
        self.end_time = input("請輸入結束時間(yyyymmdd): ")
        pattern = r'^\d{8}$'
        while True:
            if re.match(pattern, self.end_time):
                try:
                    datetime.strptime(self.end_time, '%Y%m%d')
                    break
                except ValueError:
                    self.end_time = input(colored("日期錯誤，請輸入日期格式 yyyymmdd: ", "yellow"))
            else:
                self.end_time = input(colored("日期錯誤，請輸入日期格式 yyyymmdd: ", "yellow"))
        return self.end_time
            
    # get detection details in a time range
    def detection_details(self, detection_type, directory):
        print("working on ---> requests.post")
        payload = {
            "filter": {
                "assignee": [".none"],
                "ticket_id": [".none"],
                "status": [".none"],
                "resolution": [".none"],
                "types": detection_type,
                "risk_score_min": 0
            },
            "from": int(datetime.timestamp(datetime.strptime(self.start_time, "%Y%m%d")))*1000,
            "limit": 200,
            "offset": 0,
            "sort": [{
                "direction": "desc",
                "field": "ID"
            }],
            "until": int(datetime.timestamp(datetime.strptime(self.end_time, "%Y%m%d"))+86399)*1000,
        }
        detections = self.post_info("detections/search", payload).json()

        with open(f"{directory}/{self.start_time}~{self.end_time}.json", "w") as fw:
            json.dump(detections, fw)
    
class metrics(ExtrahopApi):
    def __init__(self):
        super().__init__()





