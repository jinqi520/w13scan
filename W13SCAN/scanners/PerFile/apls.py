#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 4:45 PM
# @Author  : w8ay
# @File    : jsonp.py

import string
from urllib.parse import urlparse

import pyjsparser
import requests
import json
import re

from pyjsparser import parse

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase
from lib.helper.helper_sensitive import sensitive_bankcard, sensitive_idcard, sensitive_phone, sensitive_email
from lib.helper.jscontext import analyse_Literal


class W13SCAN(PluginBase):
    name = '查找apls接口'
    desc = '''apls接口未授权访问会有很多敏感信息，
    参考：https://niemand.com.ar/2021/01/08/exploiting-application-level-profile-semantics-apls-from-spring-data-rest/'''

    def audit(self):
        if "application/hal+json" in self.response.headers.get('Content-Type'):
            headers = self.requests.headers
            r = requests.get(self.requests.url, headers=headers, timeout=30)
            result = self.new_result()
            result.init_info(self.requests.url, "存在apls接口", VulType.SENSITIVE)
            result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                              "发现apls接口:{}".format(self.requests.url), "", "", PLACE.GET)
            self.success(result)
