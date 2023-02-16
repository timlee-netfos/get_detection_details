import time
import requests
import pandas as pd
import json
import os
from dotenv import load_dotenv
from datetime import datetime

# rewrite from Python Automated VT API v3 IP address and URL analysis 2.0 by Brett Fullam
# can get entire python files by $ git clone https://github.com/b-fullam/Automating-VirusTotal-APIv3-for-IPs-and-URLs.git


# ////////////////////////////////// START URL REPORT REQUEST

# this is the function that will take user input or input from a list to submit urls/ips to VirusTotal for url/ip reports, receive and format the returned json for generating our html reports

def virustotal_Ip(Ip):
    # load_dotenv will look for a .env file and if it finds one it will load the environment variables from it
    load_dotenv()

    """
    /////  IMPORTANT  /////
    ADD .env to gitignore to keep it from being sent to github
    and exposing your API key in the repository
    """

    # retrieve API key from .env file and store in a variable
    API_KEY = os.getenv("vt_API_KEY")

    # user input, ip or url, to be submitted for a url analysis stored in the target_url variable
    target_ip = Ip

    # amend the virustotal apiv3 url to include the unique generated url_id
    url = "https://www.virustotal.com/api/v3/ip_addresses/" + target_ip


    # while you can enter your API key directly for the "x-apikey" it's not recommended as a "best practice" and should be stored-accessed separately in a .env file (see comment under "load_dotenv()"" for more information
    headers = {
        "Accept": "application/json",
        "x-apikey": API_KEY
    }

    response = requests.request("GET", url, headers=headers)

    # load returned json from virustotal into a python dictionary called decodedResponse
    decodedResponse = json.loads(response.text)
 
    # create the hypertext link to the virustotal.com report
    vt_urlReportLink = ("https://www.virustotal.com/gui/ip-address/" + target_ip)

    # strip the "data" and "attribute" keys from the decodedResponse dictionary and only include the keys listed within "attributes" to create a more concise list stored in a new dictionary called a_json
    filteredResponse = (decodedResponse["data"]["attributes"])

    # simplify last_analysis_stats attribute in order to further usage
    # get malicious detection
    last_analysis_malicious = filteredResponse['last_analysis_stats']['malicious']
    last_analysis_all = sum(filteredResponse['last_analysis_stats'].values())

    filteredResponse["security vendors' analysis"] = f'{last_analysis_malicious}/{last_analysis_all}'
    filteredResponse['ip'] = Ip

    # create an array of keys to be removed from attributes to focus on specific content for quicker/higher-level analysis
    '''
    keys_to_remove = [
        "last_analysis_results",
        "last_analysis_stats",
        "whois_date",
        'jarm',
        'network',
        'last_https_certificate_date',
        'crowdsourced_context',
        'asn',
        'last_modification_date',
        'total_votes',
        'last_https_certificate',
        'continent',
        'whois'
        ]
    

    # iterate through the filteredResponse dictionary using the keys_to_remove array and pop to remove additional keys listed in the array
    for key in keys_to_remove:
        filteredResponse.pop(key, None)
    '''

    # create a dataframe with the remaining keys stored in the filteredResponse dictionary
    # orient="index" is necessary in order to list the index of attribute keys as rows and not as columns
    dataframe = pd.DataFrame([filteredResponse])
    dataframe = dataframe.set_index('ip', drop=False)

    return dataframe.T 


# ////////////////////////////////// END URL REPORT REQUEST

# print(virustotal_Ip('8.8.8.8').T)

