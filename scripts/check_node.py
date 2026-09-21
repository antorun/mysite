import base64
import requests
import json
import re
def checknood(nood):
    noodinfo = ''
    if nood.startswith('vmess'):
        nood = nood.replace('vmess://','')
        nood = json.loads(base64.b64decode(nood).decode('utf-8'))
        noodinfo = nood['add']+':'+nood['port']
    if nood.startswith('ss://'):
        pattern = r'@([^?]+)\#'
        matches = re.findall(pattern, nood)
        if matches:
            noodinfo = matches[0]
        else:
            print("not find")
    if nood.startswith('trojan') or nood.startswith('vless://'):
        pattern = r'@([^?]+)\?'
        matches = re.findall(pattern, nood)
        if matches:
            noodinfo = matches[0]
        else:
            print("not find")
    return noodinfo     