from lib.core.data import logger, KB
from lib.core.conn import getredis
from lib.parse.parse_request import FakeReq
from lib.parse.parse_responnse import FakeResp
import traceback
import time
import random
import base64
import binascii
import json


def start():
    logger.info("Myscan Python Moudle Listen ...")
    red = getredis()
    try:
        while True:
            try:
                if True:
                    data = red.rpop("burpdata")
                    if data:
                        logger.debug("Get one data from burpdata")
                        dictdata = None
                        try:
                            dictdata = json.loads(data)
                        except Exception as ex:
                            logger.warning("Process burpdata to json get error:" + str(ex))
                            continue
                        if dictdata is not None:
                            url = dictdata.get("url").get('url')
                            request = dictdata.get("request")
                            response = dictdata.get("response")
                            request_bodyoffset = int(dictdata.get("request").get("bodyoffset"))
                            response_bodyoffset = int(dictdata.get("response").get("bodyoffset"))
                            request_raw = base64.b64decode(dictdata.get("request").get("raw"))[request_bodyoffset:]
                            response_raw = base64.b64decode(dictdata.get("response").get("raw"))[response_bodyoffset:]
                            req = FakeReq(url, request.get('headers'), request.get('method'), request_raw)
                            resp = FakeResp(int(response.get('status')), response_raw, response.get('headers'))
                            KB['task_queue'].put(('loader', req, resp))
                    else:
                        time.sleep(random.uniform(1, 2))

            except Exception as ex:
                logger.debug("Run start get error:{}".format(ex))
                traceback.print_exc()
                continue
    except KeyboardInterrupt as ex:
        logger.warning("Ctrl+C was pressed ,aborted program")