#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/12 5:19 PM
# @Author  : w8ay
# @File    : backup_folder.py
# refer:https://www.t00ls.net/viewthread.php?tid=47698&highlight=%E5%A4%87%E4%BB%BD
# refer:https://www.t00ls.net/viewthread.php?tid=45430&highlight=%E5%A4%87%E4%BB%BD

import os
import re

import requests

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'spring api未关闭'
    desc = '''spring api未关闭导致信息泄漏或rce'''

    def audit(self):
        list = [
            "env",
            "actuator/env",
            "appenv",
            "actuator/appenv"
        ]
        url = self.requests.url.rstrip("/")
        directory = os.path.basename(url)
        headers = self.requests.headers
        result = self.new_result()
        result.init_info(self.requests.url, "spring api 泄漏", VulType.BRUTE_FORCE)
        flag = False
        for payload in list:
            test_url = directory + "/" + payload
            try:
                r = requests.get(test_url, headers=headers, allow_redirects=False, stream=True)
            except requests.exceptions.MissingSchema:
                continue
            if r.status_code == 200 and "java.vm.version" in r.text:
                flag = True
                result.add_detail("payload请求" + payload, test_url, generateResponse(r),
                                  "spring api 泄漏：" + test_url, "", "", PLACE.GET)
        if flag:
            self.success(result)
