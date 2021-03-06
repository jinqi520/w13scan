#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/2 8:40 PM
# @Author  : w8ay
# @File    : function.py
import base64
import binascii
import re
import json


def is_base64(value: str):
    """
    成功返回解码后的值，失败返回False
    :param value:
    :return:
    """
    regx = '^[a-zA-Z0-9\+\/=\%]+$'
    if not re.match(regx, value):
        return False
    try:
        ret = base64.b16decode(value).decode(errors='ignore')
    except binascii.Error:
        return False
    return ret


def isJavaObjectDeserialization(value):
    if len(value) < 10:
        return False
    if value[0:5].lower() == "ro0ab":
        ret = is_base64(value)
        if not ret:
            return False
        if bytes(ret).startswith(bytes.fromhex("ac ed 00 05")):
            return True
    return False


def isPHPObjectDeserialization(value: str):
    if len(value) < 10:
        return False
    if value.startswith("O:") or value.startswith("a:"):
        if re.match('^[O]:\d+:"[^"]+":\d+:{.*}', value) or re.match('^a:\d+:{(s:\d:"[^"]+";|i:\d+;).*}', value):
            return True
    elif (value.startswith("Tz") or value.startswith("YT")) and is_base64(value):
        ret = is_base64(value)
        if re.match('^[O]:\d+:"[^"]+":\d+:{.*}', value) or re.match('^a:\d+:{(s:\d:"[^"]+";|i:\d+;).*}', ret):
            return True
    return False


def isPythonObjectDeserialization(value: str):
    if len(value) < 10:
        return False
    ret = is_base64(value)
    if not ret:
        return False
    # pickle binary
    if value.startswith("g"):
        if bytes(ret).startswith(bytes.fromhex("8003")) and ret.endswith("."):
            return True

    # pickle text versio
    elif value.startswith("K"):
        if (ret.startswith("(dp1") or ret.startswith("(lp1")) and ret.endswith("."):
            return True
    return False


def isjwt(jwtstr: str):
    if re.search('eyJ[A-Za-z0-9_\/+-]*\.eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*', jwtstr):
        try:
            signing_input, crpyto_segment = jwtstr.encode().rsplit(b'.', 1)
            header_segement, payload_segment = signing_input.split(b'.', 1)
            header = base64.b64decode(header_segement).decode()
            header_json = json.loads(header)
            if header_json['alg'] is not None:
                return True
        except Exception as e:
            return False
    return False


if __name__ == '__main__':
    str = "eyJhbGciOiJIUzI1NiIsInR5cCI6pXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    if isjwt(str):
        print("是jwt字符串")
    else:
        print("不是jwt字符串")
