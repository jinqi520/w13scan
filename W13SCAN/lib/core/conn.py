#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : conn.py
import sys
import redis
from lib.core.data import logger, conf, KB, conn


def getredis():
    return redis.StrictRedis(connection_pool=conn.redis)


def redis_conn():
    arg_redis = conf.redis
    if arg_redis:
        if "@" in arg_redis:
            pwd, ipport = arg_redis.split("@", 1)
            if not pwd:
                pwd = None
            if ":" in ipport and ipport.count(".") >= 2:
                ip, port, db = ipport.split(":", 2)
            else:
                ip = ipport
                port = 6379
                db = 0
            logger.info("Redis connection args: pwd:{},ip:{},port:{},db:{}".format(pwd, ip, port, db))
            conn.redis = redis.ConnectionPool(max_connections=300, host=ip, password=pwd, port=int(port), db=int(db))
            getredis()
    else:
        # error_msg = "Set reids connection error,please check redis-server"
        error_msg = "Please use --redis pass@host:port:db ,if pass is none ,like --redis @host:port:db"
        logger.warning(error_msg)
        sys.exit()


def set_conn():
    try:
        redis_conn()
        red = getredis()
        if not red.ping():
            error_msg = "redis ping error . will exit program"
            logger.warning(error_msg)
            sys.exit()
        else:
            logger.info("Redis ping success")
    except Exception as ex:
        error_msg = " connnect redis get error {}:please use --redis pass@host:port:db ,if pass is none ,like --redis @host:port:db".format(
            ex)
        logger.warning(error_msg)
        sys.exit()

    # TODO 其他连接方式


def cleandb():
    # red = redis.StrictRedis(connection_pool=conn.redis)
    red = getredis()
    red.flushall()
    red.close()
