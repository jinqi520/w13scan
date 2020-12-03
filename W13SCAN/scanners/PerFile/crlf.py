
import os
import requests

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase
from urllib.parse import urlparse
from lib.helper import parse_url


class W13SCAN(PluginBase):
    name = 'crlf 注入'
    desc = '''crlf 注入'''

    def audit(self):
        # 目前只检测get请求
        if self.requests.method == "GET":
            payloads_header = [
                "\r\nTestInject: myscan",
                "\r\n\tTestInject: myscan",
                "\r\n TestInject: myscan",
                "\r\tTestInject: myscan",
                "\nTestInject: myscan",
                "\rTestInject: myscan",
                "%0ATestInject: myscan/..",
                "%3F%0DTestInject: myscan",
                "%E5%98%8A%E5%98%8DTestInject: myscan",
                "%0d%0aTestInject: myscan",
                r"\r\nCTestInject: myscan",
                # twitter crlf
                "嘊嘍TestInject: myscan",
                # nodejs crlf
                "čĊTestInject: myscan",
            ]
            # 载入各请求类型的对应参数
            iterdatas = self.generateItemdatas()
            for origin_dict, positon in iterdatas:
                payloads = self.paramsCombination(origin_dict, positon, payloads_header)
                # key是被替换的参数的key   value是是被替换的参数的值 new_value是使用的payload  payload是替换后的所有参数集，直接放入requests
                for key, value, new_value, payload in payloads:
                    r = self.req(positon, payload)
                    if "TestInject" in r.headers.keys():
                        result = self.new_result()
                        result.init_info(self.requests.url, "crlf 漏洞", VulType.CRLF)
                        result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                      "payload" + payload, "", "", PLACE.GET)
                        self.success(result)


if __name__ == "__main__":
    response = requests.get("http://www.baidu.com", allow_redirects=False)
    print(response)
    if "Server" in list(response.headers.keys()):
        print(response.headers['Server'])
    result = urlparse("http://www.baidu.com:80/asd/asd.html?asdasd=qseqwe&jinqi=qwe#sadq")
    print(result)
    print(parse_url.getnoparse_url("http://www.baidu.com:80/"))
    print(parse_url.geturl_ext("http://www.baidu.com:80/"))
