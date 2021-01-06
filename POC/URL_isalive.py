import requests
from bs4 import BeautifulSoup
from requests.packages import urllib3
urllib3.disable_warnings()

def spider(urls,time):
    """
    :return:status_code
    """
    s = requests.session()
    s.trust_env = False
    s.verify = False
    status_code = None
    s.headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36'
        }
    try:
        req = s.get(urls, headers=s.headers, 
                    timeout=time, 
                    allow_redirects=True)

        content_type_header = req.headers['content-type']
        if '=' in content_type_header:
            charset = content_type_header.split('=')[1]
        else:
            charset = "gb2312"
        #print(charset)
        soup = BeautifulSoup(req.text, 'lxml') #创建 beautifulsoup 对象
        content = "{},{}".format(req.status_code,
                                        soup.title.string.encode(charset, errors='ignore').decode(charset))[:13]
    except AttributeError as e:
        return "{},{}".format(req.status_code,None)[:10]
    except Exception as ConnectTimeout:
        print('请求 %s 超时'%urls)
        return None
    except Exception as e:
        print('请求 %s 出现异常 %s'%(urls,type(e)))
        return None
    return content

def check(**kwargs):
    try:
        urls = kwargs['url']#/*str*/
        content = spider(urls,time=2)
        if content == None:
            content = spider(urls.replace('http','https'),time=2)
            return content
        else:
            return content
    except Exception as e:
        print('执行脚本出错 %s'%e)


if __name__ == "__main__":
    urls = 'http://60.174.230.245:8090'
    content = spider(urls,time=2)
    if content == None:
        print('error')
    else:
        print(content)
    
















