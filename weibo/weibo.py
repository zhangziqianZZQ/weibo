# -*- coding: utf-8 -*-
import requests # 用于发送post或get请求
import time # 用户获取时间戳 在函数getTimeStamp()被调用
import json # 用户解析服务器返回的json数据到字典
import base64 # 用于将字符串编码成base64编码，在login函数中，su参数是用户名base64编码后的字符串
import rsa # rsa加密，在login函数中，用于将用户密码通过pubkey加密
import binascii # 用在rsa加密里的
from urllib import parse # 用于解析一个url连接，这里用于将例如https://www.baidu.com?&a=1&b=2一个网址解析出他的host（www.baidu.com） 和查询参数 （a=1&b=2）
from bs4 import BeautifulSoup # 解析html结构，从html中解析和获取数据


# 定义获取时间戳函数，返回一个13位的整数时间戳
def getTimeStamp():
    return int(time.time() * 1000)


# 通过访问微博接口，获取接口返回的servertime，nonce，pubkey，rsakv这几个参数
def getPublicKey(userName):
    # 将userName base64编码
    userName = base64.b64encode(userName.encode()).decode()

    # 定义接口
    api = 'https://login.sina.com.cn/sso/prelogin.php'

    # 构造请求的参数
    data = {
        'entry': 'weibo',
        'callback': 'sinaSSOController.preloginCallBack',
        'rsakt': 'mod',
        'su': userName,
        'client': 'ssologin.js(v1.4.19)',
        '_': getTimeStamp()
    }

    # 构造请求的header协议头
    header = {
        'Referer': 'https://weibo.com/',
    }

    # 发起一个get请求，请求地址是api，参数是data，协议头是header，响应是req
    req = session.get(api, params=data, headers=header)

    # 处理响应文本（req.text），提取中间的json字符串
    result = req.text.replace('sinaSSOController.preloginCallBack(', '')
    result = result.replace(')', '')

    # 解析响应json字符串到python的字典
    res = json.loads(result)

    # 返回提取到的下列参数
    return res['servertime'], res['nonce'], res['pubkey'], res['rsakv']


# 定义登录函数，通过userName, userPwd, nonce, rsakv这几个参数登录
def login(userName, userPwd, nonce, rsakv):
    # 将userName base64编码
    userName = base64.b64encode(userName.encode()).decode()

    # 登录api
    api = f'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)&_={getTimeStamp()}'

    # 构造登录参数
    data = {
        'entry': 'weibo',
        'gateway': 1,
        'from': '',
        'savestate': 7,
        'qrcode_flag': False,
        'useticket': 1,
        'pagerefer': 'https://passport.weibo.com/',
        'vsnf': 1,
        'su': userName,
        'service': 'miniblog',
        'servertime': int(time.time()),
        'nonce': nonce,
        'pwencode': 'rsa2',
        'rsakv': rsakv,
        'sp': userPwd,
        'sr': '1920*1080',
        'encoding': 'UTF-8',
        'cdult': 2,
        'domain': 'weibo.com',
        'prelt': 115,
        'returntype': 'TEXT'
    }

    req = session.post(api, data)
    res = req.json()
    return res['protection_url']


# rsa加密函数
def encryptPwd(serverTime, nonce, pubkey, userPwd):
    publicKey = rsa.PublicKey(int(pubkey, 16), int('10001', 16))
    pubkeyStr = f'{serverTime}\t{nonce}\n{userPwd}'
    sStr = rsa.encrypt(pubkeyStr.encode(), publicKey)
    sp = binascii.b2a_hex(sStr).decode()
    return sp


def getRedirects(url):
    # 因为url中有URL编码字符，首先将他解码
    # 例如一个url是https%3A%2F%2Fwww.baidu.com%2F%3F
    # 这里的%3A%2F%2F其实就是://只不过是URL编码了，先把他解码
    url = parse.unquote(url)

    # 解析url
    res = parse.urlparse(url)

    # 得到url中的参数 https://www.baidu.com?a=1&b=2
    # 这里的a=1&b=2就是参数
    tokenStr = res.query

    token = tokenStr.split('=')[1]

    # 用session发起一个get请求，目标是url
    req = session.get(url)

    # 用BeautifulSoup库解析响应的html
    soup = BeautifulSoup(req.text, 'html.parser')

    # 在解析的html中，通过选择器来选择页面中id="ss0"的标签，
    l = soup.find('input', id='ss0')

    # 获取这个标签的value属性值，这个也就是加密后的手机
    # 得到这个加密后的手机，可以向他发送短信验证码
    encryptMobile = l['value']
    return token, encryptMobile


# 发送短信验证码
def sendCode(token, encryptMobile):
    # 跟之前的类似，都是定义一个api请求接口，然后构造请求参数，然后发起一个get或者post响应，然后解析响应
    api = f'https://passport.weibo.com/protection/mobile/sendcode?token={token}'
    data = {
        'encrypt_mobile': encryptMobile
    }
    req = session.post(api, data)
    print(f'发送验证码结果：{req.text}')


# 校验验证码
def checkCode(token, encryptMobile, code):
    api = f'https://passport.weibo.com/protection/mobile/confirm?token={token}'
    data = {
        'encrypt_mobile': encryptMobile,
        'code': code
    }
    req = session.post(api, data)

    # 请求都跟之前的步骤一样，验证码如果校验成功，在响应中会有下一步的跳转地址，解析响应并获取下一个跳转地址res['data']['redirect_url']
    res = req.json()

    return res['data']['redirect_url']



# 请求一个跳转地址
def getRedirectsLogin(redirectsLoginUrl):
    req = session.get(redirectsLoginUrl)

    # 从响应中处理获得需要的跳转地址
    left = req.text.index('replace("') + 9
    right = req.text.index('")')

    redirectsTxz = req.text[left:right]
    return redirectsTxz


# 请求一个跳转地址
def getRedirectsTxz(redirectsTxz):
    req = session.get(redirectsTxz)

    # 从响应中处理获得需要的跳转地址
    left = req.text.index('setCrossDomainUrlList(') + 22
    right = req.text.index(')')
    urlStr = req.text[left:right]
    j = json.loads(urlStr)
    return j['arrURL'][0]


# 请求passport地址
def getPassport(url):
    req = session.get(url)

    # 到这里上一个请求发完就是已经登录成功了
    print(req.text)
    result = req.text.replace('(', '')
    result = result.replace(');', '')

    # json.load()函数用于将一个json字符串解析成python的字典
    res = json.loads(result)
    print(f"用户{res['userinfo']['displayname']}已登录")

    # 将请求的cookie转换成字典格式然后json处理后输出，这一句可要可不要，因为已经登录成功了
    a = json.dumps(req.cookies.get_dict())
    print(a)


if __name__ == '__main__':
    # 实例化一个requests请求的session会话，以保持后面的请求都是同一个请求，cookie会自动合并
    # 如果不用session相当于每个请求时独立的，用session的话，后面的请求相当于是同一个身份
    session = requests.session()

    userName = '13167556201'
    userPwd = 'zzq19971205'

    # 调用getPublicKey函数获取下列几个参数
    serverTime, nonce, pubkey, rsakv = getPublicKey(userName)

    # 将明文密码通过rsa加密
    userPwd = encryptPwd(serverTime, nonce, pubkey, userPwd)

    # 调用登录函数，如果登录成功需要验证，取出下一步的跳转连接redirects
    redirects = login(userName, userPwd, nonce, rsakv)

    # 通过get访问跳转连接获取token和加密后的手机号
    token, encryptMobile = getRedirects(redirects)

    # 短信验证码登录验证身份，这个函数是发送短信验证码
    sendCode(token, encryptMobile)

    # 从控制台得到用户输入的短信验证码
    code = input('请输入验证码：')

    # 通过调用校验验证码函数checkCode来获取下一步的跳转连接redirectsLogin
    redirectsLogin = checkCode(token, encryptMobile, code)

    # 通过get访问redirectsLogin跳转连接得到新浪通行证的跳转连接redirectsTxz
    redirectsTxz = getRedirectsLogin(redirectsLogin)

    # 通过get访问通行证连接获取passport跳转连接passportUrl
    passportUrl = getRedirectsTxz(redirectsTxz)

    # get请求passport连接，登录成功
    getPassport(passportUrl)