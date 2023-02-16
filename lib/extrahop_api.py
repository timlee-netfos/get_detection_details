# rewrite from ExtraHop code-example
# https://github.com/ExtraHop/code-examples/tree/main/py_rx360_auth
# License: https://github.com/ExtraHop/code-examples/blob/main/LICENSE

import requests
import base64
from dotenv import load_dotenv
import os

class ExtrahopApi:
    def __init__(self):
        self.load_customer()
        self.load_config()
        self.token = None
    
    def load_customer(self):
        self.customer = input("請輸入客戶名稱(netfos, realtek...): ")
        while True:
            with open("customers.txt", "r") as fr:
                customers = fr.read().strip("\n")
            if self.customer not in customers:
                self.customer = input("客戶名稱錯誤，請重新輸入: ")
            else: 
                break

    def load_config(self):
        load_dotenv()
        self.HOST = os.getenv(f"{self.customer}_HOST")
        self.ID = os.getenv(f"{self.customer}_ID")
        self.SECRET = os.getenv(f"{self.customer}_SECRET")
    
    def get_token(self):
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
        headers = {"Authorization": "Bearer " + self.token}
        url = self.HOST + "/api/v1" + f"/{page}"
        r = requests.get(url, headers=headers)
        return r
    
    def post_info(self, page, payload):
        headers = {"Authorization": "Bearer " + self.token}
        url = self.HOST + "/api/v1" + f"/{page}"
        r = requests.post(url, headers=headers, json=payload)
        return r


    






