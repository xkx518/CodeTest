<h1 align="center" >Welcome to CodeTest</h1>


### :point_right:关于本项目

>本项目的主要目的：针对日常收集的Python POC\EXP测试脚本，使用可视化界面统一执行入口，方便运行。
>
>本项目适合人群：有Python基础的渗透测试人员（工具自带简易编辑器，可修改脚本内参数，重新加载后可灵活使用脚本进行测试）
>
>可视化界面开发库：Tkinter


### :bulb:POC\EXP 参考链接

```
https://github.com/Ascotbe/Medusa
https://github.com/zhzyker/vulmap
```


### :book:使用说明

```
# 下载文件
git clone https://github.com/xkx518/CodeTest.git
cd CodeTest
# 安装依赖
pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
注意: Python\Python36\Lib\site-packages，找到这个路径，下面有一个文件夹叫做crypto,将小写c改成大写C
# 使用工具
双击 CodeTest.pyw
pythonw3 CodeTest.pyw

###如果GitHub图片显示不出来，修改hosts

C:\Windows\System32\drivers\etc\hosts

在文件末尾添加
# GitHub Start 
192.30.253.112    Build software better, together 
192.30.253.119    gist.github.com
151.101.184.133    assets-cdn.github.com
151.101.184.133    raw.githubusercontent.com
151.101.184.133    gist.githubusercontent.com
151.101.184.133    cloud.githubusercontent.com
151.101.184.133    camo.githubusercontent.com
151.101.184.133    avatars0.githubusercontent.com
151.101.184.133    avatars1.githubusercontent.com
151.101.184.133    avatars2.githubusercontent.com
151.101.184.133    avatars3.githubusercontent.com
151.101.184.133    avatars4.githubusercontent.com
151.101.184.133    avatars5.githubusercontent.com
151.101.184.133    avatars6.githubusercontent.com
151.101.184.133    avatars7.githubusercontent.com
151.101.184.133    avatars8.githubusercontent.com

 # GitHub End
```


### :checkered_flag:模板
#### POC

```
def check(**kwargs):
	url = kwargs['url']#/*str*/
	port = kwargs['port']#/*str*/
	print('输出结果')
	print(url)
	print(port)
	if True:
		return 1
	else:
		return
```


#### EXP

```
import CodeTest
from ClassCongregation import _urlparse
#VULN = None => 漏洞测试
#VULN = True => 命令执行
CodeTest.VULN = None

def check(**kwargs):
    if CodeTest.VULN == None:
        ExpApacheShiro = ApacheShiro(_urlparse(kwargs['url']),"echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpApacheShiro = ApacheShiro(_urlparse(kwargs['url']),kwargs['cmd'])
    if kwargs['pocname'] == "cve_2016_4437":
        ExpApacheShiro.cve_2016_4437()
    else:
        ExpApacheShiro.cve_2016_4437()
```


### :clipboard:界面介绍
#### 漏洞扫描界面
![漏洞扫描界面](https://github.com/xkx518/CodeTest/blob/master/img/1.png "漏洞扫描界面")

#### 漏洞利用界面
![漏洞利用界面](https://github.com/xkx518/CodeTest/blob/master/img/2.png "漏洞利用界面")


### :open_file_folder:使用示例
#### 1：FOFA收集链接
>FOFA脚本主要是根据"FOFA语法"收集链接
![FOFA](https://github.com/xkx518/CodeTest/blob/master/img/3.png "FOFA")

>非登录情况下，只能收集一页数据，通过获取登录后的session字段，即可获取五页数据
![FOFA](https://github.com/xkx518/CodeTest/blob/master/img/4.png "FOFA")

>修改请求session
![FOFA](https://github.com/xkx518/CodeTest/blob/master/img/5.png "FOFA")

>获取更多结果
![FOFA](https://github.com/xkx518/CodeTest/blob/master/img/6.png "FOFA")


#### 2：JSFind+URLSEO
>JSFind旨在从JS文件中找到网站相关链接
![FOFA](https://github.com/xkx518/CodeTest/blob/master/img/7.png "FOFA")

>此处可批量测试多个地址（支持文件导入和复制粘贴）
![FOFA](https://github.com/xkx518/CodeTest/blob/master/img/8.png "FOFA")

>勾选URLSEO，批量返回目标地址的状态码和Title
![FOFA](https://github.com/xkx518/CodeTest/blob/master/img/9.png "FOFA")



#### 3：shiro漏洞检测和命令执行
>命令执行一般是在此界面进行配置，配置好目的地址和测试的模块即可开始测试，下述图片显示目标存在shiro漏洞
![FOFA](https://github.com/xkx518/CodeTest/blob/master/img/10.png "FOFA")

>修改上一步获取到的key和gadget，***特别注意：通过修改VULN的值为True或None，来选择模块的功能是测试还是用于执行命令***
![FOFA](https://github.com/xkx518/CodeTest/blob/master/img/11.png "FOFA")

>保存，重新载入后输入需要执行的命令，即可输出命令执行的结果
![FOFA](https://github.com/xkx518/CodeTest/blob/master/img/12.png "FOFA")

>当然，你也可以选择测试所有模块
![FOFA](https://github.com/xkx518/CodeTest/blob/master/img/13.png "FOFA")

