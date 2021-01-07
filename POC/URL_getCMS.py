import copy
import time,urllib3
import types
import re,random,requests
from config import ruleDatas,USER_AGENTS

urllib3.disable_warnings()

class AttribDict(dict):
    """
    This class defines the dictionary with added capability to access members as attributes
    """

    def __init__(self, indict=None, attribute=None):
        if indict is None:
            indict = {}

        # Set any attributes here - before initialisation
        # these remain as normal attributes
        self.attribute = attribute
        dict.__init__(self, indict)
        self.__initialised = True

        # After initialisation, setting attributes
        # is the same as setting an item

    def __getattr__(self, item):
        """
        Maps values to attributes
        Only called if there *is NOT* an attribute with this name
        """

        try:
            return self.__getitem__(item)
        except KeyError:
            raise AttributeError("unable to access item '%s'" % item)

    def __setattr__(self, item, value):
        """
        Maps attributes to values
        Only if we are initialised
        """

        # This test allows attributes to be set in the __init__ method
        if "_AttribDict__initialised" not in self.__dict__:
            return dict.__setattr__(self, item, value)

        # Any normal attributes are handled normally
        elif item in self.__dict__:
            dict.__setattr__(self, item, value)

        else:
            self.__setitem__(item, value)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __deepcopy__(self, memo):
        retVal = self.__class__()
        memo[id(self)] = retVal

        for attr in dir(self):
            if not attr.startswith('_'):
                value = getattr(self, attr)
                if not isinstance(value, (types.BuiltinFunctionType, types.FunctionType, types.MethodType)):
                    setattr(retVal, attr, copy.deepcopy(value, memo))

        for key, value in self.items():
            retVal.__setitem__(key, copy.deepcopy(value, memo))

        return retVal

class ruleInfo():
    def __init__(self, WebInfos):
        self.rex = re.compile('<title>(.*?)</title>')
        self.WebInfos = WebInfos

    def main(self):
        for cms in ruleDatas:
            rulesRegex = re.compile(ruleDatas[cms]['regex'])
            if 'headers' == ruleDatas[cms]['type']:
                result = self.heads(rulesRegex, cms)
                if result:
                    return result
            else:
                result = self.bodys(rulesRegex, cms)
                if result:
                    return result
        webTitle = ""
        webServer = ""
        for key in self.WebInfos:
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
            else:
                webServer = "None"
            webTitles = re.findall(self.rex, self.WebInfos[key][1])
            if webTitles:
                webTitle = webTitles[0]
            else:
                webTitle = "None"
            print("[{0}]".format(time.strftime("%H:%M:%S", time.localtime(
            ))), webServer, self.WebInfos[key][2], key, webTitle)
        return webServer
        

    def heads(self, rulesRegex, cms):
        webTitle = ""
        webServer = ""
        for key in list(self.WebInfos):
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
            else:
                webServer = "None"
            webTitles = re.findall(self.rex, self.WebInfos[key][1])
            if webTitles:
                webTitle = webTitles[0]
            else:
                webTitle = "None"
            for head in self.WebInfos[key][0]:
                resHeads = re.findall(rulesRegex, self.WebInfos[key][0][head])
                if resHeads:
                    print("[{0}]".format(time.strftime("%H:%M:%S", time.localtime(
                    ))), cms, webServer, self.WebInfos[key][2], key, webTitle)
                    return cms

    def bodys(self, rulesRegex, cms):
        webTitle = ""
        webServer = ""
        for key in list(self.WebInfos):
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
            else:
                webServer = "None"
            webTitles = re.findall(self.rex, self.WebInfos[key][1])
            if webTitles:
                webTitle = webTitles[0]
            else:
                webTitle = "None"
            resCodes = re.findall(rulesRegex, self.WebInfos[key][1])
            if resCodes:
                print("[{0}]".format(time.strftime("%H:%M:%S", time.localtime(
                ))), cms, webServer, self.WebInfos[key][2], key, webTitle)
                return cms


class webInfo():
    def __init__(self, target, WebInfos):
        self.headers = {
            "User-Agent": random.choice(USER_AGENTS),
        }
        self.target = target
        self.WebInfos = WebInfos



    def run(self):
        s = requests.Session()
        s.keep_alive = False
        s.headers = self.headers
        # s.mount("http://", HTTPAdapter(max_retries=3))
        # s.mount("https://", HTTPAdapter(max_retries=3))
        s.verify = False
        shiroCookie = {'rememberMe': '1'}
        s.cookies.update(shiroCookie)
        try:
            req = s.get(self.target, timeout=2)
            webHeaders = req.headers
            webCodes = req.text
            self.WebInfos[self.target] = webHeaders, webCodes, req.status_code
            req.close()
            return True
        except requests.exceptions.ReadTimeout:
            print("[{0}]".format(time.strftime("%H:%M:%S", time.localtime(
                ))), self.target, '请求超时')
            return None
        except requests.exceptions.ConnectionError:
            print("[{0}]".format(time.strftime("%H:%M:%S", time.localtime(
                ))), self.target, '连接错误')
            return None
        except requests.exceptions.ChunkedEncodingError:
            print("[{0}]".format(time.strftime("%H:%M:%S", time.localtime(
                ))), self.target, '编码错误')
            return None
        except Exception as e:
            print("[{0}]".format(time.strftime("%H:%M:%S", time.localtime(
                ))), self.target, '未知错误')
            return None


print("[*]识别CMS同时判断链接是否存活!")
def check(**kwargs):
    WebInfos = AttribDict()
    try:
        urls = kwargs['url']#/*str*/
        WebInfos_1 = webInfo(urls, WebInfos)
        WebInfos_2 = webInfo(urls.replace('http','https'), WebInfos)

        if WebInfos_1.run():
            ruleInfos = ruleInfo(WebInfos_1.WebInfos)
            webServer = ruleInfos.main()
            return webServer
        elif WebInfos_2.run():
            ruleInfos = ruleInfo(WebInfos_2.WebInfos)
            webServer = ruleInfos.main()
            return webServer
        else:
            return None
    except Exception as e:
        print('执行脚本出错 %s'%e)


if __name__ == "__main__":
    check(**{'url':'http://www.baidu.com'})
