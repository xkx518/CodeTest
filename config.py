###################基础输出环境配置###################
VUL_EXP = {
    'ApacheActiveMQ': ['cve_2015_5254','cve_2016_3088'],
    'ApacheShiro': ['cve_2016_4437'],
    'ApacheSolr': ['cve_2017_12629','cve_2019_0193','cve_2019_17558'],
    'ApacheStruts2': ['s2_005', 's2_008', 's2_009', 's2_013', 's2_015', 's2_016', 's2_029', 's2_032', 's2_045', 's2_046', 's2_048', 's2_052', 's2_057', 's2_059', 's2_061', 's2_devMode'],
    'ApacheTomcat': ['tomcat_examples','cve_2017_12615','cve_2020_1938'],
    'ApacheUnomi': ['cve_2020_13942'],
    'Drupal': ['cve_2018_7600', 'cve_2018_7602', 'cve_2019_6340'],
    'Elasticsearch': ['cve_2014_3120','cve_2015_1427'],
    'Jenkins': ['cve_2017_1000353','cve_2018_1000861'],
    'Nexus': ['cve_2019_7238','cve_2020_10199'],
    'OracleWeblogic': ['cve_2014_4210', 'cve_2017_3506', 'cve_2017_10271', 'cve_2018_2894', 'cve_2019_2725', 'cve_2019_2729', 'cve_2020_2551', 'cve_2020_2555', 'cve_2020_2883', 'cve_2020_14882'],
    'RedHatJBoss': ['cve_2010_0738','cve_2010_1428','cve_2015_7501'],
    'ThinkPHP': ['cve_2018_20062','cve_2019_9082'],
    'Fastjson': ['cve_2017_18349_24','cve_2017_18349_47']
}

headers = {
    'Accept': 'application/x-shockwave-flash,'
              'image/gif,'
              'image/x-xbitmap,'
              'image/jpeg,'
              'image/pjpeg,'
              'application/vnd.ms-excel,'
              'application/vnd.ms-powerpoint,'
              'application/msword,'
              '*/*',
    'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
    'Content-Type':'application/x-www-form-urlencoded'
}

ruleDatas = {
    "Shiro": {
        "regex": "(=deleteMe|rememberMe=)",
        "type": "headers",
    },
    "宝塔-BT.cn": {
        "regex": "(app.bt.cn/static/app.png|安全入口校验失败)",
        "type": "code",
    },
    "Nexus": {
        "regex": "(<title>Nexus Repository Manager</title>)",
        "type": "code",
    },
    "Harbor": {
        "regex": "(<title>Harbor</title>)",
        "type": "code",
    },
    "禅道": {
        "regex": "(/theme/default/images/main/zt-logo.png)",
        "type": "code",
    },
    "xxl-job": {
        "regex": "(分布式任务调度平台XXL-JOB)",
        "type": "code",
    },
    "weblogic": {
        "regex": "(/console/framework/skins/wlsconsole/images/login_WebLogic_branding.png|Welcome to Weblogic Application Server|<i>Hypertext Transfer Protocol -- HTTP/1.1</i>)",
        "type": "code",
    },
    "用友致远oa": {
        "regex": "(/seeyon/USER-DATA/IMAGES/LOGIN/login.gif)",
        "type": "code",
    },
    "Typecho": {
        "regex": "(Typecho</a>)",
        "type": "code",
    },
    "金蝶EAS": {
        "regex": "(easSessionId)",
        "type": "code",
    },
    "phpMyAdmin": {
        "regex": "(/themes/pmahomme/img/logo_right.png)",
        "type": "code",
    },
    "H3C-AM8000": {
        "regex": "(AM8000)",
        "type": "code",
    },
    "360企业版": {
        "regex": "(360EntWebAdminMD5Secret)",
        "type": "code",
    },
    "H3C公司产品": {
        "regex": "(service@h3c.com)",
        "type": "code",
    },
    "H3C ICG 1000": {
        "regex": "(ICG 1000系统管理)",
        "type": "code",
    },
    "Citrix-Metaframe": {
        "regex": "(window.location=\\\"/Citrix/MetaFrame)",
        "type": "code",
    },
    "H3C ER5100": {
        "regex": "(ER5100系统管理)",
        "type": "code",
    },
    "阿里云CDN": {
        "regex": "(cdn.aliyuncs.com)",
        "type": "code",
    },
    "CISCO_EPC3925": {
        "regex": "(Docsis_system)",
        "type": "code",
    },
    "CISCO ASR": {
        "regex": "(CISCO ASR)",
        "type": "code",
    },
    "H3C ER3200": {
        "regex": "(ER3200系统管理)",
        "type": "code",
    },
    "万户ezOFFICE": {
        "regex": "(LocLan)",
        "type": "headers",
    },
    "万户网络": {
        "regex": "(css/css_whir.css)",
        "type": "code",
    },
    "Spark_Master": {
        "regex": "(Spark Master at)",
        "type": "code",
    },
    "华为_HUAWEI_SRG2220": {
        "regex": "(HUAWEI SRG2220)",
        "type": "code",
    },
    "蓝凌EIS智慧协同平台": {
        "regex": "(/scripts/jquery.landray.common.js)",
        "type": "code",
    },
    "深信服ssl-vpn": {
        "regex": "(login_psw.csp)",
        "type": "code",
    },
    "华为 NetOpen": {
        "regex": "(/netopen/theme/css/inFrame.css)",
        "type": "code",
    },
    "Citrix-Web-PN-Server": {
        "regex": "(Citrix Web PN Server)",
        "type": "code",
    },
    "juniper_vpn": {
        "regex": "(welcome.cgi\\?p=logo|/images/logo_juniper_reversed.gif)",
        "type": "code",
    },
    "360主机卫士": {
        "regex": "(zhuji.360.cn)",
        "type": "headers",
    },
    "Nagios": {
        "regex": "(Nagios Access)",
        "type": "headers",
    },
    "H3C ER8300": {
        "regex": "(ER8300系统管理)",
        "type": "code",
    },
    "Citrix-Access-Gateway": {
        "regex": "(Citrix Access Gateway)",
        "type": "code",
    },
    "华为 MCU": {
        "regex": "(McuR5-min.js)",
        "type": "code",
    },
    "TP-LINK Wireless WDR3600": {
        "regex": "(TP-LINK Wireless WDR3600)",
        "type": "code",
    },
    "泛微协同办公OA": {
        "regex": "(ecology_JSessionid)",
        "type": "headers",
    },
    "华为_HUAWEI_ASG2050": {
        "regex": "(HUAWEI ASG2050)",
        "type": "code",
    },
    "360网站卫士": {
        "regex": "(360wzb)",
        "type": "code",
    },
    "Citrix-XenServer": {
        "regex": "(Citrix Systems, Inc. XenServer)",
        "type": "code",
    },
    "H3C ER2100V2": {
        "regex": "(ER2100V2系统管理)",
        "type": "code",
    },
    "zabbix": {
        "regex": "(images/general/zabbix.ico)",
        "type": "code",
    },
    "CISCO_VPN": {
        "regex": "(webvpn)",
        "type": "headers",
    },
    "360站长平台": {
        "regex": "(360-site-verification)",
        "type": "code",
    },
    "H3C ER3108GW": {
        "regex": "(ER3108GW系统管理)",
        "type": "code",
    },
    "o2security_vpn": {
        "regex": "(client_param=install_active)",
        "type": "headers",
    },
    "H3C ER3260G2": {
        "regex": "(ER3260G2系统管理)",
        "type": "code",
    },
    "H3C ICG1000": {
        "regex": "(ICG1000系统管理)",
        "type": "code",
    },
    "CISCO-CX20": {
        "regex": "(CISCO-CX20)",
        "type": "code",
    },
    "H3C ER5200": {
        "regex": "(ER5200系统管理)",
        "type": "code",
    },
    "linksys-vpn-bragap14-parintins": {
        "regex": "(linksys-vpn-bragap14-parintins)",
        "type": "code",
    },
    "360网站卫士常用前端公共库": {
        "regex": "(libs.useso.com)",
        "type": "code",
    },
    "H3C ER3100": {
        "regex": "(ER3100系统管理)",
        "type": "code",
    },
    "H3C-SecBlade-FireWall": {
        "regex": "(js/MulPlatAPI.js)",
        "type": "code",
    },
    "360webfacil_360WebManager": {
        "regex": "(publico/template/)",
        "type": "code",
    },
    "Citrix_Netscaler": {
        "regex": "(ns_af)",
        "type": "code",
    },
    "H3C ER6300G2": {
        "regex": "(ER6300G2系统管理)",
        "type": "code",
    },
    "H3C ER3260": {
        "regex": "(ER3260系统管理)",
        "type": "code",
    },
    "华为_HUAWEI_SRG3250": {
        "regex": "(HUAWEI SRG3250)",
        "type": "code",
    },
    "exchange": {
        "regex": "(/owa/auth.owa)",
        "type": "code",
    },
    "Spark_Worker": {
        "regex": "(Spark Worker at)",
        "type": "code",
    },
    "H3C ER3108G": {
        "regex": "(ER3108G系统管理)",
        "type": "code",
    },
    "深信服防火墙类产品": {
        "regex": "(SANGFOR FW)",
        "type": "code",
    },
    "Citrix-ConfProxy": {
        "regex": "(confproxy)",
        "type": "code",
    },
    "360网站安全检测": {
        "regex": "(webscan.360.cn/status/pai/hash)",
        "type": "code",
    },
    "H3C ER5200G2": {
        "regex": "(ER5200G2系统管理)",
        "type": "code",
    },
    "华为（HUAWEI）安全设备": {
        "regex": "(sweb-lib/resource/)",
        "type": "code",
    },
    "H3C ER6300": {
        "regex": "(ER6300系统管理)",
        "type": "code",
    },
    "华为_HUAWEI_ASG2100": {
        "regex": "(HUAWEI ASG2100)",
        "type": "code",
    },
    "TP-Link 3600 DD-WRT": {
        "regex": "(TP-Link 3600 DD-WRT)",
        "type": "code",
    },
    "NETGEAR WNDR3600": {
        "regex": "(NETGEAR WNDR3600)",
        "type": "code",
    },
    "H3C ER2100": {
        "regex": "(ER2100系统管理)",
        "type": "code",
    },
    "绿盟下一代防火墙": {
        "regex": "(NSFOCUS NF)",
        "type": "code",
    },
    "jira": {
        "regex": "(jira.webresources)",
        "type": "code",
    },
    "金和协同管理平台": {
        "regex": "(金和协同管理平台)",
        "type": "code",
    },
    "Citrix-NetScaler": {
        "regex": "(NS-CACHE)",
        "type": "code",
    },
    "linksys-vpn": {
        "regex": "(linksys-vpn)",
        "type": "headers",
    },
    "通达OA": {
        "regex": "(/static/images/tongda.ico)",
        "type": "code",
    },
    "华为（HUAWEI）Secoway设备": {
        "regex": "(Secoway)",
        "type": "code",
    },
    "华为_HUAWEI_SRG1220": {
        "regex": "(HUAWEI SRG1220)",
        "type": "code",
    },
    "H3C ER2100n": {
        "regex": "(ER2100n系统管理)",
        "type": "code",
    },
    "H3C ER8300G2": {
        "regex": "(ER8300G2系统管理)",
        "type": "code",
    },
    "金蝶政务GSiS": {
        "regex": "(/kdgs/script/kdgs.js)",
        "type": "code",
    },
    "Jboss": {
        "regex": "(Welcome to JBoss|jboss.css)",
        "type": "code",
    },
}


USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729; InfoPath.3; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
    "Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
    "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; en) Presto/2.8.131 Version/11.11",
    "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Maxthon 2.0)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; TencentTraveler 4.0)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; The World)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SE 2.X MetaSr 1.0; SE 2.X MetaSr 1.0; .NET CLR 2.0.50727; SE 2.X MetaSr 1.0)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Avant Browser)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
    "Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5",
    "Mozilla/5.0 (iPod; U; CPU iPhone OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5",
    "Mozilla/5.0 (iPad; U; CPU OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5",
    "Mozilla/5.0 (Linux; U; Android 2.3.7; en-us; Nexus One Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
    "MQQBrowser/26 Mozilla/5.0 (Linux; U; Android 2.3.7; zh-cn; MB200 Build/GRJ22; CyanogenMod-7) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
    "Opera/9.80 (Android 2.3.4; Linux; Opera Mobi/build-1107180945; U; en-GB) Presto/2.8.149 Version/11.10",
    "Mozilla/5.0 (Linux; U; Android 3.0; en-us; Xoom Build/HRI39) AppleWebKit/534.13 (KHTML, like Gecko) Version/4.0 Safari/534.13",
    "Mozilla/5.0 (BlackBerry; U; BlackBerry 9800; en) AppleWebKit/534.1+ (KHTML, like Gecko) Version/6.0.0.337 Mobile Safari/534.1+",
    "Mozilla/5.0 (hp-tablet; Linux; hpwOS/3.0.0; U; en-US) AppleWebKit/534.6 (KHTML, like Gecko) wOSBrowser/233.70 Safari/534.6 TouchPad/1.0",
    "Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 NokiaN97-1/20.0.019; Profile/MIDP-2.1 Configuration/CLDC-1.1) AppleWebKit/525 (KHTML, like Gecko) BrowserNG/7.1.18124",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0; HTC; Titan)",
    "UCWEB7.0.2.37/28/999",
    "NOKIA5700/ UCWEB7.0.2.37/28/999",
    "Openwave/ UCWEB7.0.2.37/28/999",
    "Mozilla/4.0 (compatible; MSIE 6.0; ) Opera/UCWEB7.0.2.37/28/999",
    "Mozilla/6.0 (iPhone; CPU iPhone OS 8_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/8.0 Mobile/10A5376e Safari/8536.25",
]

VULN = True
DEBUG = None
DELAY = 0
TIMEOUT = 10
OUTPUT = None
CMD = "echo VuLnEcHoPoCSuCCeSS"
RUNALLPOC = False