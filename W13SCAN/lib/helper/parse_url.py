from urllib.parse import urlparse


def getnoparse_url(url):
    result = urlparse(url)
    return result.scheme + "://" + result.netloc + result.path


def geturl_ext(url):
    return getnoparse_url(url).split(".")[-1]
