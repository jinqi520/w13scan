#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/10 4:26 PM
# @Author  : w8ay
# @File    : swf_files.py

from urllib.parse import urlparse

import requests

from lib.core.common import generateResponse, md5
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '动态渲染导致的ssrf'

    def audit(self):
        p = urlparse(self.requests.url)

        arg = "{}://{}/".format(p.scheme, p.netloc)
        headers = {
            "User-Agent": "curl/7.54.0"
        }
        response = requests.get(arg + "render?url=http://www.example.com", herders=headers)
        if "<h1>Example Domain</h1>" in response.text:
            result = self.new_result()
            result.init_info(self.requests.url, "动态渲染导致的ssrf", VulType.SSRF)
            result.add_detail("payload请求", response.reqinfo, generateResponse(response),
                              "存在ssrf漏洞尝试：{}".format(arg + "render?url=http://www.example.com"), "", "", PLACE.GET)
            self.success(result)
        headers = {
            "User-Agent": "Slackbot blabla"
        }
        response = requests.get(arg, herders=headers)
        if response.headers.get("X-Renderer") is not None and "Rendertron" == response.headers.get("X-Renderer"):
            result = self.new_result()
            result.init_info(self.requests.url, "动态渲染导致的ssrf", VulType.SSRF)
            result.add_detail("payload请求", response.reqinfo, generateResponse(response),
                              '可能存在ssrf漏洞尝试：curl -A "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)" {}redirectUrl=http://www.example.com/'.format(arg), "", "", PLACE.GET)
            self.success(result)
