from lib.virustotal_api import virustotal_api

vt_API = virustotal_api()
with open("data/unable_check_ip.txt", "r") as fr:
    vt_API.not_check_ip = fr.read().split("\n")
print(len(vt_API.not_check_ip))
vt_API.multiple_ip_check(vt_API.not_check_ip)
