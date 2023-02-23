# Introduction
- Access ExtroHop API in order to finish daily monitoring and regular reports
- practice oop 
- build setting automation instead of adding configuration manually

# Modules Installation
- Python version: 3.9 or above
- install modules
```powershell
$ pip install -r requirements.txt
```

# Program Execution
- execute python program
```powershell
$ python \path\to\directory\c2_ip_inspect.py
```
- first time execution
	- input api configuration
	- input virustotal api key
- input variables
	- customer name (netfos for testing)
	- time interval

# .env Configuration
- configuration
	- vt_API_KEY:
		- sign up virustotal and get api key
		- standard free api key has a limitation of 500 lookups / day
	- {customer}_HOST: 
		- The hostname of the Reveal(x) 360 API displayed in the Reveal(x) 360 API Access page under API Endpoint (api endpoint but not include the /oauth/token)
	- {customer}_ID: 
		- The ID of the REST API credentials
	- {customer}_SECRET: 
		- The secret of the REST API credentials

# Reference
- virustotal_api.py
	- rewrite from Python Automated VT API v3 IP address and URL analysis 2.0 by Brett Fullam
	- https://github.com/b-fullam/Automating-VirusTotal-APIv3-for-IPs-and-URLs.git
- extrahop_api.py
	- rewrite from ExtraHop code-example
	- https://github.com/ExtraHop/code-examples/tree/main/py_rx360_auth