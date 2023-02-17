import requests
import base64
import json
from dotenv import load_dotenv
import os
import pandas as pd
from lib import virustotal_api
from lib.extrahop_api import ExtrahopApi
import ipaddress
from datetime import datetime
import re 

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
                    self.start_time = input("日期錯誤，請輸入日期格式 yyyymmdd: ")
            else:
                self.start_time = input("日期錯誤，請輸入日期格式 yyyymmdd: ")
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
                    self.end_time = input("日期錯誤，請輸入日期格式 yyyymmdd: ")
            else:
                self.end_time = input("日期錯誤，請輸入日期格式 yyyymmdd: ")
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
                "types": [detection_type],
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