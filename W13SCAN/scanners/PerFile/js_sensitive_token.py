#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 9:55 PM
# @Author  : w8ay
# @File    : sensitive_content.py
# referer:https://github.com/al0ne/Vxscan/blob/master/lib/jsparse.py
import re

from lib.core.enums import VulType, PLACE
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'js文件敏感内容匹配'
    desc = '''从返回js的包中匹配敏感内容'''

    def audit(self):
        if self.requests.suffix != ".js":
            return

        regs = {
            "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
            "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
            "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
            "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
            "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "Amazon AWS Access Key ID": "AKIA[0-9A-Z]{16}",
            "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "AWS API Key": "AKIA[0-9A-Z]{16}",
            "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
            "Facebook OAuth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
            "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
            "Generic API Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
            "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
            "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
            "Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
            "Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
            "Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
            "Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
            "Google (GCP) Service-account": "\"type\": \"service_account\"",
            "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
            "Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
            "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
            "Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
            "Google YouTube OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
            "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
            "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
            "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
            "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
            "Picatic API Key": "sk_live_[0-9a-z]{32}",
            "Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
            "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
            "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
            "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
            "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
            "Twilio API Key": "SK[0-9a-fA-F]{32}",
            "Twitter Access Token": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
            "Twitter OAuth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
        }
        finds = []
        msg = ""
        for key in regs:
            results = re.findall(regs[key], self.response.text, re.M | re.I)
            if len(results) != 0:
                for result in results:
                    if len(result) < 100:
                        finds.append(key)
                        msg = msg + "根据{}的正则表达式:{} 发现敏感信息:{} \n".format(key, regs[key], result)
        if len(finds) > 0:
            result = ResultObject(self)
            result.init_info(self.requests.url, "js文件中存在token敏感信息", VulType.SENSITIVE)
            result.add_detail("payload探测", self.requests.raw, self.response.raw,
                              msg, "", "", PLACE.GET)
            self.success(result)
