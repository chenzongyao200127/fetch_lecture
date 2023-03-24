import requests
import random
from Crypto.Cipher import AES
import base64
import re
from urllib.parse import quote
import json
from pprint import pprint

def pkcs7Pad(data):
    blockSize = 16
    paddingLen = blockSize - len(data)%blockSize
    padding = bytes([paddingLen])*paddingLen
    return data + padding

def passwdAddSalt(passwd, salt):
    charChoices = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
    paddingBlock = ''
    for _ in range(64):
        paddingBlock += random.choice(charChoices)
    iv = ''
    for _ in range(16):
        iv += (random.choice(charChoices))
    rawTxt = (paddingBlock + passwd).encode('UTF-8')
    rawSalt = salt.encode('UTF-8')
    rawIv = iv.encode('UTF-8')
    cryptor = AES.new(rawSalt, 2, rawIv)
    plaintxt = pkcs7Pad(rawTxt)
    saltedPasswd = base64.b64encode(cryptor.encrypt(plaintxt))
    return saltedPasswd

def searchCasLoginInfo(html):
    reSearchTxt = r'<input type="hidden" name="lt" value="(.*)"/>\s*<input type="hidden" name="dllt" value="(.*)"/>\s*<input type="hidden" name="execution" value="(.*)"/>\s*<input type="hidden" name="_eventId" value="(.*)"/>\s*<input type="hidden" name="rmShown" value="(.*)">\s*<input type="hidden" id="pwdDefaultEncryptSalt" value="(.*)"/>'
    rePattern = re.compile(reSearchTxt)
    result = rePattern.search(html)
    casLoginInfo = {
        'lt': result.group(1),
        'dllt': result.group(2),
        'execution': result.group(3),
        '_eventId': result.group(4),
        'rmShown': result.group(5),
        'pwdDefaultEncryptSalt': result.group(6)
    }
    return casLoginInfo

def seuLogin(username, passwd):
    sess = requests.session()
    loginHeaders = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'
    }
    sess.headers = loginHeaders
    loginUrl = 'https://newids.seu.edu.cn/authserver/login?goto='
    serviceUrl = 'http://my.seu.edu.cn/index.portal'
    serviceRedirectUrl = loginUrl + quote(serviceUrl)

    response = sess.get(loginUrl)
    responseHtml = response.text
    casLoginInfo = searchCasLoginInfo(responseHtml)
    saltedPasswd = passwdAddSalt(passwd, casLoginInfo['pwdDefaultEncryptSalt'])

    form = {
        'username': username,
        'password': saltedPasswd,
        'lt': casLoginInfo['lt'],
        'dllt': casLoginInfo['dllt'],
        'execution': casLoginInfo['execution'],
        '_eventId': casLoginInfo['_eventId'],
        'rmShown': casLoginInfo['rmShown']
    }

    response = sess.post(loginUrl, form)
    response = sess.get('http://ehall.seu.edu.cn/login?service=http://ehall.seu.edu.cn/new/index.html')
    response = sess.get('http://ehall.seu.edu.cn/jsonp/userDesktopInfo.json')

    resInfo = json.loads(response.text)
    pprint(resInfo)

if __name__ == "__main__":
    seuLogin('220224769', 'Happy200127boy!')