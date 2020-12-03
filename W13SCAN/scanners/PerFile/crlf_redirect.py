
import os
import requests

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase
from urllib.parse import urlparse


class W13SCAN(PluginBase):
    name = 'uri重定向'
    desc = '''uri重定向'''

    def audit(self):
        result = urlparse(self.requests.url)
        path = result.path
        if self.requests.method == "GET" and self.response.status_code == 302 and self.response.headers['Location'] in path:
            result = self.new_result()
            result.init_info(self.requests.url, "uri重定向或crlf", VulType.REDIRECT)
            result.add_detail("uri重定向", self.requests.url, generateResponse(self.response),
                              "尝试将uri改为http://www.evil.com进行重定向测试", "", "", PLACE.GET)
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36"
            }
            response = requests.get(result.scheme + "://" + result.netloc + path + "%0d%0ajinqi:%20crlf_test", headers=headers, allow_redirects=False)
            if "jinqi" in response.headers.keys():
                result.add_detail("crlf", result.scheme + ":" + result.netloc + path + "%0d%0ajinqi:%20crlf_test", generateResponse(response),
                                  "尝试使用如上url进行crlf测试", "", "", PLACE.GET)
            self.success(result)
