import asyncio
import copy
import datetime
import json
import logging
import os
import queue
import re
import socket
import socketserver
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from logging.handlers import TimedRotatingFileHandler
from threading import Lock
from threading import Thread

import jwt
import psutil
import requests
import schedule
from dns.resolver import Resolver
from dnslib import DNSRecord, QTYPE, DNSHeader, RR, A
from flask import Flask, request, jsonify, redirect

app = Flask(__name__, static_folder='static', static_url_path='')


def create_token(data, timeout=120):
    headers = {
        'type': 'jwt',
        'alg': 'HS256'
    }
    payload = {'data': data, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=timeout)}
    result = jwt.encode(payload=payload, key=JWT_SALT, algorithm='HS256', headers=headers)
    return result


def parse_payload(token):
    result = {
        'status': False,
        'data': None,
        'error': None
    }

    try:
        verified_payload = jwt.decode(token, JWT_SALT, algorithms='HS256')
        result['status'] = True
        result['data'] = verified_payload
    except jwt.exceptions.ExpiredSignatureError:
        result['error'] = 'token已失效'
    except jwt.DecodeError:
        result['error'] = 'token认证失败'
    except jwt.InvalidTokenError:
        result['error'] = '非法的token'
    return result


class LogFilter:
    @staticmethod
    def info_filter(record):
        if record.levelname == 'INFO':
            return True
        return False

    @staticmethod
    def error_filter(record):
        if record.levelname == 'ERROR':
            return True
        return False


class TimeLoggerRolloverHandler(TimedRotatingFileHandler):
    def __init__(self, filename, when='h', interval=1, backupCount=0, encoding='utf-8', delay=False, utc=False):
        super(TimeLoggerRolloverHandler, self).__init__(filename, when, interval, backupCount, encoding, delay, utc)

    def doRollover(self):
        """
        TimedRotatingFileHandler对日志的切分是在满足设定的时间间隔后，执行doRollover方法，
        将my.log重命名为带有当前时间后缀(my.log.****)的文件，并新建一个my.log，继续记录后续日志。
        (1) 重写TimedRotatingFileHandler的doRollover方法的文件翻转块代码
        做了以下两点改动：
            重定义了新文件名，将日期放在了中间而不是最后
            直接将将baseFilename 指向新文件
        """
        if self.stream:
            self.stream.close()
            self.stream = None
        currentTime = int(time.time())
        dstNow = time.localtime(currentTime)[-1]

        log_type = 'info' if self.level == 20 else 'error'
        # 重新定义了新文件名
        base_dir = os.path.dirname(self.baseFilename)[:-11]
        datetime_now = datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S').split('_')
        date_now = datetime_now[0]
        time_now = datetime_now[1]
        file_date = '/'.join(date_now.split('-'))  # '2022/07/11/15/13/35'
        log_dir = f'{base_dir}/{file_date}'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        dfn = f"{log_dir}/{time_now}.{log_type}.log"
        if os.path.exists(dfn):
            os.remove(dfn)

        print(self.baseFilename, '...before')
        self.baseFilename = dfn  # 直接将将baseFilename 指向新文件
        print(self.baseFilename, '...after')

        if not self.delay:
            self.stream = self._open()
        newRolloverAt = self.computeRollover(currentTime)
        while newRolloverAt <= currentTime:
            newRolloverAt = newRolloverAt + self.interval
        if (self.when == 'MIDNIGHT' or self.when.startswith('W')) and not self.utc:
            dstAtRollover = time.localtime(newRolloverAt)[-1]
            if dstNow != dstAtRollover:
                if not dstNow:
                    addend = -3600
                else:
                    addend = 3600
                newRolloverAt += addend
        self.rolloverAt = newRolloverAt


def get_myProjectLogger(project_name, log_file_name, elk, when='H', interval=1):
    base_dir = f"./log_{project_name}"
    datetime_now = datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S').split('_')
    date_now = datetime_now[0]
    time_now = datetime_now[1]
    file_date = '/'.join(date_now.split('-'))  # '2022/07/11/15/13/35'
    log_dir = f'{base_dir}/{file_date}'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    log_error_file = f"{log_dir}/{time_now}.error.log"
    log_info_file = f"{log_dir}/{time_now}.info.log"

    error_handler = TimeLoggerRolloverHandler(log_error_file, when=when, interval=interval)
    error_handler.addFilter(LogFilter.error_filter)
    error_handler.setFormatter(formatter)
    error_handler.setLevel(logging.ERROR)

    info_handel = TimeLoggerRolloverHandler(log_info_file, when=when, interval=interval)
    info_handel.addFilter(LogFilter.info_filter)
    info_handel.setFormatter(formatter)
    info_handel.setLevel(logging.INFO)

    level = logging.INFO
    logger = logging.getLogger(log_file_name)
    logger.setLevel(level=level)  # 设置日志基础级别

    if elk['enable']:
        sh = MySocketHandler(elk['host'], elk['port'])
        sh.encoding = 'utf-8'
        sh.setFormatter(formatter)
        logger.addHandler(sh)

    logger.addHandler(info_handel)
    logger.addHandler(error_handler)
    # LOG
    return logger


class MySocketHandler(logging.handlers.SocketHandler):
    def makePickle(self, record):
        # 将日志消息格式化为字符串
        msg = self.format(record)

        # 将日志中的所有换行符去除
        msg = msg.replace('\n', ' ')

        # 给每条日志加上分隔符 方便logstash解析
        msg += '\n'

        # 将字符串转换为字节流
        msg = msg.encode('utf-8')

        # 返回字节流
        return msg


class DateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return json.JSONEncoder.default(self, obj)


class Config:
    not_allow = []
    allow = []
    not_request = []
    return_ip = {}
    not_response = []
    can_request = []
    request_blacklist = []
    response_blacklist = []
    cache = {}
    pool = ThreadPoolExecutor(1)
    write_file_pool = ThreadPoolExecutor(1)
    write_dangerous_domain_logger_file_pool = ThreadPoolExecutor(1)
    lock = Lock()
    filename = 'ip.json'
    total_filename = 'total.json'
    config_filename = 'config.json'
    dns_servers = []
    filter_rule = []
    is_filter = False
    screen_rule = []
    is_screen = False
    is_deduplicate = False
    immobilization = {}
    ip = {}
    refresh_time = 0
    port = 53
    web_port = 53
    log_num = 20
    dns_resolver = Resolver()
    check_dns_resolver = Resolver()
    refresh_cache_time = 0
    fail_login_num = 0
    login_wait_second = 2
    username = ''
    password = ''
    is_fresh = False
    config = {}
    admin_ip = '127.0.0.1'
    use_cache_bak = False
    symbol = '✦'
    refresh_job = None
    get_config_job = None
    config_job_start = False
    refresh_job_start = False
    need_clean_cache_key_list = ['not_allow', 'allow', 'not_request', 'response_blacklist', 'return_ip', 'not_response',
                                 'can_request', 'request_blacklist', 'screen_rule', 'filter_rule', 'immobilization',
                                 'dnsservers']
    need_enable_and_re_compile_list = ['not_allow', 'allow', 'not_request', 'response_blacklist', 'request_blacklist',
                                       'filter_rule', 'dangerous_domain']
    need_to_int_list = ['refresh_cache_time', 'refresh_time', 'port', 'web_port', 'log_num', 'login_wait_second']
    need_handle_ip_list = ['return_ip', 'immobilization']
    need_generate_ip_range_list = ['not_response', 'can_request']

    def __init__(self):
        self.cache = self.select_all()
        self.cache_bak = copy.deepcopy(self.cache)
        with open(os.path.join(base_dir, self.config_filename), encoding='utf-8', mode='r') as f:
            config = json.loads(f.read())
            self.config = config
        self.elk = config['elk']
        self.server = config['server']
        self.not_allow = self.get_enable_and_re_compile_list(config['not_allow'])
        self.allow = self.get_enable_and_re_compile_list(config['allow'])
        self.not_request = self.get_enable_and_re_compile_list(config['not_request'])
        self.not_response = Config.generate_ip_range(config['not_response'])
        self.can_request = Config.generate_ip_range(config['can_request'])
        self.request_blacklist = self.get_enable_and_re_compile_list(config['request_blacklist'])
        self.response_blacklist = self.get_enable_and_re_compile_list(config['response_blacklist'])
        self.dns_servers = self.get_enable_list(config['dnsservers'])
        self.filter_rule = self.get_enable_and_re_compile_list(config['filter_rule'])
        self.screen_rule = self.get_enable_and_re_compile_list_with_not_exact_match(config['screen_rule'])
        self.dangerous_domain = self.get_enable_and_re_compile_list(config['dangerous_domain'])

        self.immobilization = Config.handle_ip(config['immobilization'])
        self.return_ip = Config.handle_ip(config['return_ip'])

        self.dns_resolver.nameservers = self.get_enable_list(config['dnsservers'])
        print('使用的dns服务器为： ', self.dns_resolver.nameservers)
        self.log_num = config['log_num']
        self.port = config['port']
        self.web_port = config['web_port']
        self.is_filter = config['is_filter']
        self.is_screen = config['is_screen']
        self.is_deduplicate = config['is_deduplicate']
        self.refresh_cache_time = config['refresh_cache_time']
        self.refresh_time = config['refresh_time']
        self.username = config['username']
        self.password = config['password']
        self.login_wait_second = config['login_wait_second']
        self.admin_ip = config['admin_ip']
        self.lately_login_time = datetime.datetime.now()
        self.wait_second = 1

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, item):
        return getattr(self, item)

    @staticmethod
    def _insert(self, domain, ip):
        self.cache[domain] = {
            'ip': ip,
            'create_time': datetime.datetime.now(),
            'update_time': datetime.datetime.now(),
        }
        if self.write_file_pool is not None:
            self.write_file_pool.submit(self.write_file, self)
        else:
            self.write_file(self)

    @staticmethod
    def _update(self, domain, ip):
        self.cache[domain]['ip'] = ip
        self.cache[domain]['update_time'] = datetime.datetime.now()
        if self.write_file_pool is not None:
            self.write_file_pool.submit(self.write_file, self)
        else:
            self.write_file(self)

    def select_all(self):
        with open(os.path.join(base_dir, self.filename), encoding='utf-8', mode='r') as f:
            result_dict = json.loads(f.read())
        for i in result_dict.values():
            if 'create_time' in i:
                i['create_time'] = datetime.datetime.strptime(i['create_time'], "%Y-%m-%d %H:%M:%S")
            if 'update_time' in i:
                i['update_time'] = datetime.datetime.strptime(i['update_time'], "%Y-%m-%d %H:%M:%S")
        return result_dict

    def insert(self, domain, ip):
        if self.pool is not None:
            self.pool.submit(self._insert, self, domain, ip)
        else:
            self._insert(self, domain, ip)

    def delete(self, domain):
        del self.cache[domain]
        if self.write_file_pool is not None:
            self.write_file_pool.submit(self.write_file, self)
        else:
            self.write_file(self)

    def update(self, domain, ip):
        if self.pool is not None:
            self.pool.submit(self._update, self, domain, ip)
        else:
            self._update(self, domain, ip)

    @staticmethod
    def write_file(self):
        try:
            f = open(os.path.join(base_dir, self.filename), encoding='utf-8', mode='w')
            f.write(json.dumps(self.cache, cls=DateEncoder, ensure_ascii=False, indent=1))
            f.close()
        except Exception as e:
            print(e)

    def log(self, data):
        if self.pool is not None:
            self.pool.submit(self._log, self, data)
        else:
            self._log(self, data)

    @staticmethod
    def _log(self, data):
        qsize = log_queue.qsize()
        data_split = data.split(conf.symbol)
        q_list = list(log_queue.queue)

        try:
            address = data_split[0]
            domain = data_split[2]
        except:
            return

        if conf.is_filter:
            for filter_rule in conf.filter_rule:
                if filter_rule.search(domain):
                    return

        if conf.is_screen and len(conf.screen_rule) > 0:
            flag = False
            for screen in conf.screen_rule:
                if screen.search(data):
                    flag = True
                    break

            if not flag:
                return

        if conf.is_deduplicate:
            for i in q_list:
                if address in i and domain in i:
                    return

        if qsize >= self.log_num:
            for i in range(qsize - self.log_num + 1):
                log_queue.get()
            log_queue.put(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + data)
        else:
            log_queue.put(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + data)

    @staticmethod
    def handle_ip(data):
        result = {}
        for k, v in data.items():
            if k == 'domain':
                v = Config.get_enable_and_re_compile_list(v)
            else:
                v = [i for i in v if i['enable']]
            result[k] = v
        return result

    def get_ip_list(self):
        # 获取主机名和IP地址的列表
        host_info = socket.gethostbyname_ex(socket.gethostname())

        # 获取本机IP地址
        ip_address = host_info[2]

        return ip_address

    def set_dns(self, server):
        interfaces = psutil.net_if_addrs()
        # 遍历网卡信息，输出网卡名称
        for interface in interfaces:
            # 调用netsh命令修改DNS服务器
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "dnsservers", interface, "static", server], check=True,
                capture_output=True)
            # 输出修改后的DNS服务器地址
            subprocess.run(["netsh", "interface", "ipv4", "show", "dnsservers", interface],
                           capture_output=True)

    def check_dns_server(self, server_ip):
        try:
            conf.check_dns_resolver.nameservers = [server_ip]
            conf.check_dns_resolver.resolve('www.baidu.com', 'A')[0].to_text()
            return 1  # DNS 服务器响应正常
        except:
            return 2  # DNS 服务器不可用

    @staticmethod
    def ip_to_int(ip):
        return int.from_bytes(socket.inet_aton(ip), byteorder='big')

    def is_ip_in_range(self, ip, start_ip, end_ip):
        ip_int = self.ip_to_int(ip)
        start_ip_int = self.ip_to_int(start_ip)
        end_ip_int = self.ip_to_int(end_ip)
        return start_ip_int <= ip_int <= end_ip_int

    @staticmethod
    def generate_ip_range(data):
        data_list = []
        for i in data:
            if i is not None and i['enable']:
                if '-' not in i['data']:
                    data_list.append(re.compile(f'^{i["data"].strip()}$'))
                else:
                    start, end = i['data'].strip().split('-')
                    data_list.append(f'{Config.ip_to_int(start)}-{Config.ip_to_int(end)}')
        return data_list

    def get_cache_ip(self, domain, address, cache_data):
        if cache_data[domain]['update_time'] + datetime.timedelta(
                seconds=conf.refresh_time) < datetime.datetime.now():
            ip = conf.dns_resolver.resolve(domain, 'A')[0].to_text()
            conf.update(domain, ip)
            logger.info(f'{address[0]} 请求解析域名 {domain} 命中缓存返回的ip {ip}')
            conf.log(
                f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}命中缓存返回的ip{conf.symbol}{ip}{conf.symbol}')
            return ip
        logger.info(f'{address[0]} 请求解析域名 {domain} 命中缓存返回的ip {cache_data[domain]["ip"]}')
        conf.log(
            f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}命中缓存返回的ip{conf.symbol}{cache_data[domain]["ip"]}{conf.symbol}')
        return cache_data[domain]['ip']

    @staticmethod
    def get_enable_and_re_compile_list(data):
        return [re.compile(f'^{i["data"].strip()}$') for i in data if i is not None and i != '' and i['enable']]

    def get_enable_list(self, data):
        return [i["data"].strip() for i in data if i is not None and i != '' and i['enable']]

    def get_enable_and_re_compile_list_with_not_exact_match(self, data):
        return [re.compile(f'{i["data"].strip()}') for i in data if i is not None and i != '' and i['enable']]

    def write_dangerous_domain_logger_file(self, domain, ip):
        dangerous_domain_logger.info(f'{ip} 请求解析域名 {domain} 该域名是危险域名')
        if os.path.exists(os.path.join(base_dir, conf.total_filename)):
            with open(os.path.join(base_dir, conf.total_filename), encoding='utf-8', mode='r') as f:
                data = json.loads(f.read())
        else:
            data = {}

        if domain in data:
            if ip in data[domain]:
                data[domain][ip] += 1
            else:
                data[domain][ip] = 1
        else:
            data[domain] = {ip: 1}

        with open(os.path.join(base_dir, conf.total_filename), encoding='utf-8', mode='w') as f:
            f.write(json.dumps(data, cls=DateEncoder, indent=4, ensure_ascii=False))


class DNSServer(socketserver.DatagramRequestHandler):

    def get_ip_from_domain(self, domain, address):
        domain = domain.lower().strip()

        # 查看域名是否在缓存里
        if domain in conf.cache and not conf.use_cache_bak:
            return conf.get_cache_ip(domain, address, conf.cache)
        elif domain in conf.cache_bak and conf.use_cache_bak:
            return conf.get_cache_ip(domain, address, conf.cache_bak)

        try:
            # 查看域名是否在 固定域名和ip 里
            if 'domain' in conf.immobilization:
                for i in range(len(conf.immobilization['domain'])):
                    if conf.immobilization['domain'][i].search(domain):
                        return_ip = conf.immobilization["ip"][i]['data']
                        logger.info(f'{address[0]} 请求解析域名 {domain} 返回固定ip {return_ip}')
                        conf.log(
                            f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}返回固定ip{conf.symbol}{return_ip}{conf.symbol}')
                        return return_ip

            # 正则匹配是否是允许访问的域名
            for allow in conf.allow:
                if allow.search(domain):
                    try:
                        ip = conf.dns_resolver.resolve(domain, 'A')[0].to_text()

                        # 查看 ip 是否在 ip 黑名单里
                        for response_blacklist in conf.response_blacklist:
                            if response_blacklist.search(ip):
                                logger.info(f'{address[0]} 请求解析域名 {domain} 返回的ip在黑名单里 {ip}')
                                conf.log(
                                    f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}返回的ip在ip黑名单里{conf.symbol}{ip}{conf.symbol}')
                                return None

                        logger.info(f'{address[0]} 请求解析域名 {domain} 返回的ip {ip}')
                        conf.log(
                            f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}返回的ip{conf.symbol}{ip}{conf.symbol}')
                        conf.insert(domain, ip)
                        return ip
                    except:
                        logger.info(f'{address[0]} 请求解析域名 {domain} 返回的ip None')
                        conf.log(
                            f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}返回的ip{conf.symbol}None{conf.symbol}')
                        return None

            # 不向上请求的域名
            for not_request in conf.not_request:
                if not_request.search(domain):
                    logger.info(f'{address[0]} 请求解析域名 {domain} 不返回结果')
                    conf.log(
                        f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}不返回结果{conf.symbol}')
                    return None

            # 正则匹配请求域名是否在黑名单里
            for request_blacklist in conf.request_blacklist:
                if request_blacklist.search(domain):
                    logger.info(f'{address[0]} 请求解析域名 {domain} 被黑名单拦截')
                    conf.log(
                        f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}被黑名单拦截{conf.symbol}')
                    return None

            # 查看域名是否在 固定域名和ip 里
            if 'domain' in conf.return_ip:
                for i in range(len(conf.return_ip['domain'])):
                    if conf.return_ip['domain'][i].search(domain):
                        return_ip = conf.return_ip["ip"][i]['data']
                        logger.info(f'{address[0]} 请求解析域名 {domain} 返回固定ip {return_ip}')
                        conf.log(
                            f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}返回固定ip{conf.symbol}{return_ip}{conf.symbol}')
                        return return_ip

            # 正则匹配是否是不允许访问的域名
            for not_allow in conf.not_allow:
                if not_allow.search(domain):
                    logger.info(f'{address[0]} 请求解析域名 {domain} 是不允许访问的域名')
                    conf.log(
                        f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}是不允许访问的域名')
                    return None

            ip = conf.dns_resolver.resolve(domain, 'A')[0].to_text()

            # 查看 ip 是否在 ip 黑名单里
            for response_blacklist in conf.response_blacklist:
                if response_blacklist.search(ip):
                    logger.info(f'{address[0]} 请求解析域名 {domain} 返回的ip在ip黑名单里 {ip}')
                    conf.log(
                        f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}返回的ip在ip黑名单里{conf.symbol}{ip}{conf.symbol}')
                    return None

            conf.insert(domain, ip)
            logger.info(f'{address[0]} 请求解析域名 {domain} ip为 {ip}')
            conf.log(
                f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}ip为{conf.symbol}{ip}{conf.symbol}')
            return ip
        except Exception as e:
            logger.error(f'{address[0]} 解析域名 {domain} 解析ip异常异常为 {e}')
            return None

    def reply_for_not_found(self, income_record):
        header = DNSHeader(id=income_record.header.id, bitmap=income_record.header.bitmap, qr=1)
        header.set_rcode(0)  # 3 DNS_R_NXDOMAIN, 2 DNS_R_SERVFAIL, 0 DNS_R_NOERROR
        record = DNSRecord(header, q=income_record.q)
        return record

    def reply_for_A(self, income_record, ip, ttl=None):
        r_data = A(ip)
        header = DNSHeader(id=income_record.header.id, bitmap=income_record.header.bitmap, qr=1)
        domain = income_record.q.qname
        query_type_int = QTYPE.reverse.get('A') or income_record.q.qtype
        record = DNSRecord(header, q=income_record.q, a=RR(domain, query_type_int, rdata=r_data, ttl=ttl))
        return record

    def dns_handler(self, s, income_record, address, domain):
        try:
            qtype = QTYPE.get(income_record.q.qtype)
        except:
            qtype = 'unknown'
        if qtype == 'A':
            ip = self.get_ip_from_domain(domain, address)
            if ip:
                response = self.reply_for_A(income_record, ip=ip, ttl=60)
                s.sendto(response.pack(), address)
                return

        response = self.reply_for_not_found(income_record)
        s.sendto(response.pack(), address)

    def handle(self):
        conn = self.socket

        while True:
            try:
                message, address = conn.recvfrom(8192)
                try:
                    income_record = DNSRecord.parse(message)
                    domain = str(income_record.q.qname).strip('.')
                except:
                    logger.error(f'{address[0]} 请求解析的消息 {message} 解析此信息失败')
                    continue

                try:
                    # 正则匹配域名是否是危险域名
                    flag = False
                    for dangerous_domain in conf.dangerous_domain:
                        if re.search(dangerous_domain, domain):
                            conf.write_dangerous_domain_logger_file_pool.submit(conf.write_dangerous_domain_logger_file,
                                                                                domain, address[0])
                            conf.log(f'{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}该域名是危险域名')
                            flag = True
                            break
                    if flag:
                        continue

                    # 正则匹配请求 ip 是否在黑名单里
                    not_flag = False
                    for not_response in conf.not_response:
                        if type(not_response) == re.Pattern:
                            if not_response.search(address[0]):
                                logger.info(f'{address[0]} 请求解析域名 {domain} 该请求ip {address[0]} 被黑名单拦截')
                                conf.log(
                                    f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}该请求ip{conf.symbol}{address[0]}{conf.symbol}被黑名单拦截')
                                not_flag = True
                                break
                        else:
                            start, end = not_response.split('-')
                            if int(start) <= conf.ip_to_int(address[0]) <= int(end):
                                logger.info(f'{address[0]} 请求解析域名 {domain} 该请求ip {address[0]} 被黑名单拦截')
                                conf.log(
                                    f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}该请求ip{conf.symbol}{address[0]}{conf.symbol}被黑名单拦截')
                                not_flag = True
                                break
                    if not_flag:
                        continue

                    # 正则匹配请求 ip 是否是允许的ip
                    can_flag = False
                    for can_request in conf.can_request:
                        if type(can_request) == re.Pattern:
                            if can_request.search(address[0]):
                                self.dns_handler(conn, income_record, address, domain)
                                can_flag = True
                                break
                        else:
                            start, end = can_request.split('-')
                            if int(start) <= conf.ip_to_int(address[0]) <= int(end):
                                self.dns_handler(conn, income_record, address, domain)
                                can_flag = True
                                break

                    if can_flag:
                        continue

                    logger.info(f'{address[0]} 请求解析域名 {domain} 该请求ip {address[0]} 没有被允许')
                    conf.log(
                        f'{conf.symbol}客户端IP:{address[0]}{conf.symbol}请求解析域名{conf.symbol}{domain}{conf.symbol}该请求ip{conf.symbol}{address[0]}{conf.symbol}没有被允许')
                except Exception as e:
                    logger.error(f'{address[0]} 请求解析域名 {domain} 是否为黑名单异常异常为{e}')
            except Exception as e:
                ...


@app.route('/')
def index():
    return redirect('/index.html')


# 定义登录装饰器，判断用户是否登录
def decorator_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        authorization = request.headers.get('Authorization')
        token_result = parse_payload(authorization)
        if not token_result['status']:
            return jsonify({'code': 401})
        result = func(*args, **kwargs)
        result['token'] = create_token(conf.username)
        return jsonify(result)

    return wrapper


@app.route('/all')
@decorator_login
def all_data():
    f = open(os.path.join(base_dir, conf.config_filename), encoding='utf-8', mode='r')
    data = json.loads(f.read())
    f.close()
    return {'data': data}


@app.route('/get_ip', methods=['POST'])
@decorator_login
def get_ip():
    data = request.get_json()
    domain = data.get('domain', None)
    result = {'ip': ''}
    if domain:
        try:
            result['ip'] = conf.dns_resolver.resolve(domain, 'A')[0].to_text()
        except:
            pass
    return result


@app.route('/set_dns', methods=['POST'])
@decorator_login
def set_dns():
    data = request.get_json()
    dns_ip = data.get('dns', None)
    result = {'code': 0}
    if dns_ip:
        try:
            conf.set_dns(dns_ip)
            return result
        except:
            return {'code': 2}
    return {'code': 1}


@app.route('/get_self_ip')
@decorator_login
def get_self_ip():
    self_ip = ''
    try:
        self_ip = conf.get_ip_list()
    except:
        pass
    return {'ip': self_ip}


@app.route('/update', methods=['POST'])
@decorator_login
def update_re():
    try:
        data = request.get_json()
    except:
        return '请正确携带参数'
    update_config(data, conf)
    write_yaml(conf)
    return {'data': 'ok'}


@app.route('/log')
@decorator_login
def get_log():
    return {'data': list(log_queue.queue)[::-1]}


def update_config(data: dict, conf):
    for k, v in data.items():
        conf.config[k] = v

        if k == 'screen_rule':
            conf.screen_rule = conf.get_enable_and_re_compile_list_with_not_exact_match(v)

        elif k == 'dnsservers':
            conf.dns_resolver.nameservers = conf.get_enable_list(v)
            conf.dns_servers = conf.get_enable_list(v)

        elif k in conf.need_clean_cache_key_list:
            conf.cache = {}
            conf.write_file(conf)

        elif k in conf.need_enable_and_re_compile_list:
            conf[k] = conf.get_enable_and_re_compile_list(v)

        elif k in conf.need_to_int_list:
            conf.config[k] = int(v)
            conf[k] = int(v)

        elif k in conf.need_handle_ip_list:
            conf[k] = Config.handle_ip(v)

        elif k in conf.need_generate_ip_range_list:
            conf[k] = conf.generate_ip_range(v)
        else:
            conf.config[k] = v
            conf[k] = v

        if k == 'refresh_cache_time':
            conf.is_fresh = True
            conf.refresh_job_start = False
            schedule.cancel_job(conf.refresh_job)
            schedule_pool.submit(schedule_task)
        if k == 'server':
            conf.config_job_start = False
            schedule.cancel_job(conf.get_config_job)
            if 'time' in v:
                conf.config[k]['time'] = int(v['time'])
                conf[k]['time'] = int(v['time'])
            if 'port' in v:
                conf.config[k]['port'] = int(v['port'])
                conf[k]['port'] = int(v['port'])
            if v['enable']:
                schedule_pool.submit(schedule_get_config_task)


def check_token():
    authorization = request.headers.get('Authorization')
    token_result = parse_payload(authorization)
    if not token_result['status']:
        return '请登录后再进行操作'


def try_login(data):
    conf.lock.acquire()
    try:
        if request.remote_addr != conf.admin_ip:
            seconds = datetime.datetime.now() - datetime.timedelta(seconds=conf.wait_second)
            total_seconds = (seconds - conf.lately_login_time).total_seconds()
            if total_seconds < 0:
                return jsonify({'data': f'请等待 {-total_seconds} 秒后 再尝试登录'})

        username = data.get('username', None)
        password = data.get('password', None)
        if username == conf.username and password == conf.password:
            token = create_token(username)
            conf.wait_second = 1
            conf.fail_login_num = 0
            return jsonify({'token': token})
        else:
            if request.remote_addr != conf.admin_ip and username == conf.username:
                conf.fail_login_num += 1
                conf.wait_second = conf.login_wait_second ** conf.fail_login_num
                conf.lately_login_time = datetime.datetime.now()
            logger.error(f'{request.remote_addr} 尝试登录 用户名:{username} 密码:{password} 登录失败')
            return jsonify({'data': '登录失败'})
    finally:
        conf.lock.release()


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        return try_login(data)
    except:
        return jsonify({'data': '请正确携带参数'})


@app.route('/check_dns')
@decorator_login
def check_dns():
    result = []
    for i in conf.dns_servers:
        start = time.time()
        status = conf.check_dns_server(i)
        end = time.time() - start
        dic = {
            'ip': i,
            'result': f''
        }
        if status == 1:
            dic['result'] = f'在线/耗时:{round(end * 1000, 3)}ms'
            result.append(dic)
        elif status == 2:
            dic['result'] = f'未收到响应'
            result.append(dic)
        else:
            dic['result'] = f'报错'
            result.append(dic)
    return {'data': result}


@app.route('/remove_dangerous', methods=['POST'])
@decorator_login
def remove_dangerous():
    try:
        data = request.get_json()
        domain = data['domain']
        ip = data['ip']
    except:
        return {'data': '请正确携带参数'}
    with open(os.path.join(base_dir, conf.total_filename), encoding="utf-8", mode="r") as f:
        data = json.load(f)
    if domain not in data:
        return {'data': '操作成功'}
    if ip not in data[domain]:
        return {'data': '操作成功'}
    del data[domain][ip]
    if len(data[domain].keys()) == 0:
        del data[domain]
    with open(os.path.join(base_dir, conf.total_filename), encoding="utf-8", mode="w") as f:
        f.write(json.dumps(data, cls=DateEncoder, indent=4, ensure_ascii=False))
    return {'data': '操作成功'}


@app.route('/get_dangerous')
@decorator_login
def get_dangerous():
    if not os.path.exists(os.path.join(base_dir, conf.total_filename)):
        with open(os.path.join(base_dir, conf.total_filename), encoding="utf-8", mode="w") as f:
            f.write(json.dumps({}))
        return {'data': {}}
    with open(os.path.join(base_dir, conf.total_filename), encoding="utf-8", mode="r") as f:
        data = json.load(f)
    return {'data': data}


def write_yaml(conf):
    data = conf.config
    with open(os.path.join(base_dir, conf.config_filename), encoding="utf-8", mode="w") as f:
        f.write(json.dumps(data, cls=DateEncoder, indent=1, ensure_ascii=False))


def run():
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    print('web服务端口为：' + str(conf.web_port))
    try:
        app.run(host='0.0.0.0', port=conf.web_port, ssl_context=('server.crt', 'server.key'))
    except Exception as e:
        print(e)


async def dns_server(loop):
    print('启动的端口为：' + str(conf.port))
    server = socketserver.ThreadingUDPServer(('0.0.0.0', conf.port), DNSServer)
    await loop.run_in_executor(None, server.serve_forever)


def get_new_cache():
    now = datetime.datetime.now()
    conf.cache_bak = copy.deepcopy(conf.cache)
    conf.use_cache_bak = True
    for domain, ip_dict in conf.cache.items():
        try:
            ip_dict['ip'] = conf.dns_resolver.resolve(domain, 'A')[0].to_text()
            ip_dict['update_time'] = now
        except:
            continue
    conf.use_cache_bak = False
    conf.cache_bak = copy.deepcopy(conf.cache)
    conf.write_file_pool.submit(conf.write_file, conf)


def schedule_task():
    get_new_cache()
    conf.refresh_job_start = True
    conf.refresh_job = schedule.every(conf.refresh_cache_time).seconds.do(get_new_cache)
    while True:
        try:
            if not conf.refresh_job_start:
                break
            schedule.run_pending()
            time.sleep(1)
            if conf.is_fresh:
                conf.is_fresh = False
                break
        except Exception as e:
            logger.error(f'刷新缓存失败 {e}')
            time.sleep(1)


def schedule_get_config_task():
    conf.get_config_job = schedule.every(conf.server['time']).seconds.do(get_config)
    conf.config_job_start = True
    while True:
        try:
            if not conf.config_job_start:
                break
            schedule.run_pending()
            time.sleep(1)
        except Exception as e:
            logger.error(f'从服务端获取配置失败 {e}')
            time.sleep(1)


def get_config():
    try:
        resp = requests.get(f'https://{conf.server["host"]}:{conf.server["port"]}/get_config', verify=False)
        data = resp.json()
        update_config(data, conf)
        write_yaml(conf)
    except:
        resp = requests.get(f'http://{conf.server["host"]}:{conf.server["port"]}/get_config')
        data = resp.json()
        update_config(data, conf)
        write_yaml(conf)


def first_package():
    time.sleep(1)
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn.settimeout(0.1)
    conn.sendto(b'package', ('127.0.0.1', conf.port))


if __name__ == '__main__':
    JWT_SALT = 'fgdkljdlkfa#^&%^@$^!*^*($&@fdiskhgjfkdhfidofds*&^%&$%&'
    log_dir = "log"  # 日志存放文件夹名称
    log_path = os.getcwd() + os.sep + log_dir

    # logging 全局设置
    logging.basicConfig(level=logging.INFO, datefmt='%Y/%m/%d %H:%M:%S', filemode='a')
    LOG_FORMAT = '%(asctime)s - %(levelname)s: %(message)s'
    formatter = logging.Formatter(LOG_FORMAT, "%Y-%m-%d %H:%M:%S")

    base_dir = os.path.dirname(sys.argv[0])
    requests.packages.urllib3.disable_warnings()
    log_queue = queue.Queue()
    conf = Config()
    logger = get_myProjectLogger("dns", "log", elk=conf.elk, when='H', interval=1)
    dangerous_domain_logger = get_myProjectLogger("dangerous_domain", "dangerous_log", elk=conf.elk, when='H',
                                                  interval=1)
    pool = ThreadPoolExecutor(1)
    pool.submit(run)
    schedule_pool = ThreadPoolExecutor(2)
    if conf.server['enable']:
        schedule_pool.submit(schedule_task)
        schedule_pool.submit(schedule_get_config_task)
    else:
        schedule_pool.submit(schedule_task)
    Thread(target=first_package).start()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(dns_server(loop))
