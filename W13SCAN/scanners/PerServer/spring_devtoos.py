from urllib.parse import urlparse

import requests

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'spring devtools 反序列化漏洞'
    desc = '''spring devtools 反序列化漏洞
    https://medium.com/@sherif_ninja/springboot-devtools-insecure-deserialization-analysis-exploit-2c4ac77c285a'''

    def audit(self):
        url = self.requests.url
        p = urlparse(url)
        domain = "{}://{}/".format(p.scheme, p.netloc)
        result = self.new_result()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
            "Content-Type": "application/octet-stream",
            "AUTH-TOKEN": "jinqi123"
        }
        headers1 = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
            "Content-Type": "application/octet-stream",
            "AUTH-TOKEN": "mysecret"
        }
        vul_url = domain + "/.~~spring-boot!~/restart"
        try:
            resp = requests.post(vul_url, headers=headers, data="a", timeout=10)
            resp1 = requests.post(vul_url, headers=headers1, data="a", timeout=10)
            if resp1.status_code == 500 and resp.status_code == 403:
                result.init_info(self.requests.url, "存在spring devtools 反序列化漏洞", VulType.BRUTE_FORCE)
                result.add_detail("payload请求", resp.reqinfo, generateResponse(resp), "api接口：" + vul_url, "", "", PLACE.POST)
                self.success(result)
        except Exception as e:
            pass
