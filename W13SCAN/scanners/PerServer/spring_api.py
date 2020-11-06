from urllib.parse import urlparse

import requests
from tld import parse_tld

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase
# 加了  <artifactId>spring-boot-starter-actuator</artifactId> 依赖会有如下api开放
#         "/actuator",
#         "/auditevents",
#         "/autoconfig",
#         "/beans",
#         "/caches",
#         "/conditions",
#         "/configprops",
#         "/docs",
#         "/dump",
#         "/flyway",
#         "/health",
#         "/heapdump",
#         "/httptrace",
#         "/info",
#         "/intergrationgraph",
#         "/logfile",
#         "/loggers",
#         "/liquibase",
#         "/metrics",
#         "/mappings",
#         "/prometheus",
#         "/refresh",
#         "/scheduledtasks",
#         "/sessions",
#         "/shutdown",
#         "/trace",
#         "/threaddump"


class W13SCAN(PluginBase):
    name = 'spring boot api'
    desc = '''spring 监控接口未关闭导致信息泄漏'''

    def audit(self):
        headers = self.requests.headers
        url = self.requests.url
        p = urlparse(url)
        domain = "{}://{}/".format(p.scheme, p.netloc)
        result = self.new_result()
        try:
            list = [
                domain + "/env",
                domain + "/actuator/env",
                domain + "/appenv",
                domain + "/actuator/appenv"
                    ]
            for api_url in list:
                resp = requests.get(api_url, headers=headers, allow_redirects=False, timeout=5)
                if resp.status_code == 200 and "java.vm.version" in resp.text:
                    result.init_info(self.requests.url, "spring boot监控接口信息泄漏", VulType.BRUTE_FORCE)
                    result.add_detail("payload请求", resp.reqinfo, generateResponse(resp),
                                      "api接口：" + api_url, "", "", PLACE.GET)
                    self.success(result)
                    return
        except Exception as e:
            pass
