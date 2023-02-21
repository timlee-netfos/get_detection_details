# rewrite from ExtraHop code-example
# https://github.com/ExtraHop/code-examples/tree/main/py_rx360_auth
# License: https://github.com/ExtraHop/code-examples/blob/main/LICENSE

import requests
import base64
from dotenv import load_dotenv
import os
from termcolor import colored

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
        self.customer = input("請輸入客戶名稱: ")
        with open("data/customers.txt", "r") as fr:
            customers = fr.read().strip("\n")
        while True:
            if self.customer not in customers:
                check_wrong_customer = input(f"目前不存在客戶名稱 {self.customer}\n1. 新增客戶 2. 重新輸入: ")
                if check_wrong_customer == "1":
                    self.new_customer()
                    break
                elif check_wrong_customer == "2":
                    continue
            else: 
                break

    def new_customer(self):
        try_times = 3
        while try_times > 0:
            self.customer = input("請輸入客戶名稱: ")
            self.HOST = input("請輸入 API Endpoint: ")
            self.ID = input("請輸入 ID: ")
            self.SECRET = input("請輸入 SECRET: ")
            r = self.get_info("apikeys").status_code
            if r >= 200 and r < 300:
                with open("lib/.env", "a") as fa:
                    fa.write(f"\n{self.customer}_HOST={self.HOST}\n{self.customer}_ID={self.ID}\n{self.customer}_SECRET={self.SECRET}")
                with open("data/customers.txt", "a") as fa:
                    fa.write(f"\n{self.customer}")
                print(colored("新增客戶成功!", "yellow"))
                return None
            elif try_times > 1:
                print(colored("輸入錯誤，請重新輸入", "red"))
                try_times -= 1
                continue
            else:
                print(colored("錯誤次數已達 3 次，程式終止", "yellow"))
                exit(1)
        

    def vt_API_KEY(self):
        try_times = 3
        while try_times > 0:
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
                print(colored("新增 virustotal API KEY 成功!", "yellow"))
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


    






