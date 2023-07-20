import asyncio
import datetime
import json
import logging
import os
import queue
import re
import socket
import socketserver
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import TimedRotatingFileHandler
from threading import Lock

import psutil
import schedule
from dns.resolver import Resolver
from dnslib import DNSRecord, QTYPE, DNSHeader, RR, A
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS

app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)
log_dir = "log"  # 日志存放文件夹名称
log_path = os.getcwd() + os.sep + log_dir

# logging 全局设置
logging.basicConfig(level=logging.INFO,
                    # level=__debug__,
                    # format=log_format,
                    datefmt='%Y/%m/%d %H:%M:%S',
                    # datefmt='%a, %d %b %Y %H:%M:%S',
                    # filename='{0}.log'.format(fileName),
                    filemode='a')
LOG_FORMAT = '%(asctime)s - %(levelname)s: %(message)s'
formatter = logging.Formatter(LOG_FORMAT, "%Y-%m-%d %H:%M:%S")


def get_myLogger(fileName='xxlog.log'):
    fileName = log_path + os.sep + fileName
    level = logging.INFO
    logger = logging.getLogger(__name__)
    logger.setLevel(level=level)

    if not os.path.isdir(log_path):
        os.makedirs(log_path)

    timefilehandler = TimedRotatingFileHandler(fileName,
                                               when='midnight',
                                               interval=1,
                                               backupCount=30)
    timefilehandler.setLevel(level=level)
    timefilehandler.setFormatter(formatter)
    logger.addHandler(timefilehandler)

    logger.info("file:{0}".format(fileName))
    return logger


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
    def __init__(self, filename, when='h', interval=1, backupCount=0, encoding='utf-8', delay=False, utc=False,
                 atTime=None):
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
        # If DST changes and midnight or weekly rollover, adjust for this.
        if (self.when == 'MIDNIGHT' or self.when.startswith('W')) and not self.utc:
            dstAtRollover = time.localtime(newRolloverAt)[-1]
            if dstNow != dstAtRollover:
                if not dstNow:  # DST kicks in before next rollover, so we need to deduct an hour
                    addend = -3600
                else:  # DST bows out before next rollover, so we need to add an hour
                    addend = 3600
                newRolloverAt += addend
        self.rolloverAt = newRolloverAt


def get_myProjectLogger(project_name, log_file_name, when='H', interval=1):
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
    logger = logging.getLogger(__name__)
    logger.setLevel(level=level)  # 设置日志基础级别

    logger.addHandler(info_handel)
    logger.addHandler(error_handler)
    # LOG
    return logger


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
    lock = Lock()
    filename = 'ip.json'
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
    refresh_cache_time = 0
    is_fresh = False
    config = {}

    def __init__(self):
        self.cache = self.select_all()
        with open('config.json', encoding='utf-8', mode='r') as f:
            config = json.loads(f.read())
            self.config = config
        self.not_allow = [f'^{i["data"].strip()}$' for i in config['not_allow'] if
                          i is not None and i != '' and i['enable']]
        self.allow = [f'^{i["data"].strip()}$' for i in config['allow'] if i is not None and i != '' and i['enable']]
        self.not_request = [f'^{i["data"].strip()}$' for i in config['not_request'] if
                            i is not None and i != '' and i['enable']]
        self.not_response = [f'^{i["data"].strip()}$' for i in config['not_response'] if
                             i is not None and i != '' and i['enable']]
        self.can_request = [f'^{i["data"].strip()}$' for i in config['can_request'] if
                            i is not None and i != '' and i['enable']]
        self.request_blacklist = [f'^{i["data"].strip()}$' for i in config['request_blacklist'] if
                                  i is not None and i != '' and i['enable']]
        self.response_blacklist = [f'^{i["data"].strip()}$' for i in config['response_blacklist'] if
                                   i is not None and i != '' and i['enable']]
        self.dns_servers = [i["data"] for i in config['dnsservers'] if i is not None and i != '' and i['enable']]
        self.filter_rule = [i["data"] for i in config['filter_rule'] if i is not None and i != '' and i['enable']]
        self.screen_rule = [i["data"] for i in config['screen_rule'] if i is not None and i != '' and i['enable']]

        self.immobilization = self.handle_ip(config['immobilization'])
        self.return_ip = self.handle_ip(config['return_ip'])

        self.dns_resolver.nameservers = [i["data"] for i in config['dnsservers'] if
                                         i is not None and i != '' and i['enable']]
        print('使用的dns服务器为： ', self.dns_resolver.nameservers)
        self.log_num = config['log_num']
        self.port = config['port']
        self.web_port = config['web_port']
        self.is_filter = config['is_filter']
        self.is_screen = config['is_screen']
        self.is_deduplicate = config['is_deduplicate']
        self.refresh_cache_time = config['refresh_cache_time']
        self.refresh_time = config['refresh_time']

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
        with open(self.filename, encoding='utf-8', mode='r') as f:
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
            f = open(self.filename, encoding='utf-8', mode='w')
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
        data_split = data.split(' ')
        q_list = list(log_queue.queue)

        try:
            address = data_split[0]
            domain = data_split[2]
        except:
            return

        if conf.is_filter:
            for filter_rule in conf.filter_rule:
                if re.search(filter_rule, domain):
                    return

        if conf.is_screen:
            flag = False
            for screen in conf.screen_rule:
                if re.search(screen, domain):
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
            log_queue.put(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' ' + data)
        else:
            log_queue.put(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' ' + data)

    def handle_ip(self, data):
        result = {}
        for k, v in data.items():
            if k == 'domain':
                v = [f'^{i["data"].strip()}$' for i in v if i['enable']]
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

    def ip_to_int(self, ip):
        packed_ip = socket.inet_aton(ip)
        return struct.unpack("!I", packed_ip)[0]

    def is_ip_in_range(self, ip, start_ip, end_ip):
        ip_int = self.ip_to_int(ip)
        start_ip_int = self.ip_to_int(start_ip)
        end_ip_int = self.ip_to_int(end_ip)
        return start_ip_int <= ip_int <= end_ip_int


class DNSServer(socketserver.DatagramRequestHandler):

    def get_ip_from_domain(self, domain, address):
        domain = domain.lower().strip()

        # 查看域名是否在缓存里
        if domain in conf.cache:
            if conf.cache[domain]['update_time'] + datetime.timedelta(
                    seconds=conf.refresh_time) < datetime.datetime.now():
                ip = conf.dns_resolver.resolve(domain, 'A')[0].to_text()
                conf.update(domain, ip)
                logger.info(f'{address[0]} 请求解析域名 {domain} 命中缓存 返回的ip {ip}')
                conf.log(f'{address[0]} 请求解析域名 {domain} 命中缓存 返回的ip {ip}')
                return ip
            logger.info(f'{address[0]} 请求解析域名 {domain} 命中缓存 返回的ip {conf.cache[domain]["ip"]}')
            conf.log(f'{address[0]} 请求解析域名 {domain} 命中缓存 返回的ip {conf.cache[domain]["ip"]}')
            return conf.cache[domain]['ip']

        # 查看域名是否在 固定域名和ip 里
        if 'domain' in conf.immobilization:
            for i in range(len(conf.immobilization['domain'])):
                if re.search(conf.immobilization['domain'][i], domain):
                    return_ip = conf.immobilization["ip"][i]['data']
                    logger.info(f'{address[0]} 请求解析域名 {domain} 返回 固定ip {return_ip}')
                    conf.log(f'{address[0]} 请求解析域名 {domain} 返回 固定ip {return_ip}')
                    return return_ip

        # 正则匹配是否是允许访问的域名
        for allow in conf.allow:
            if re.search(allow, domain):
                try:
                    ip = conf.dns_resolver.resolve(domain, 'A')[0].to_text()

                    # 查看 ip 是否在 ip 黑名单里
                    for response_blacklist in conf.response_blacklist:
                        if re.search(response_blacklist, ip):
                            logger.info(f'{address[0]} 请求解析域名 {domain} 返回的ip {ip} 在ip黑名单里')
                            conf.log(f'{address[0]} 请求解析域名 {domain} 返回的ip {ip} 在ip黑名单里')
                            return None

                    # 插入数据库
                    logger.info(f'{address[0]} 请求解析域名 {domain} 返回的ip {ip}')
                    conf.log(f'{address[0]} 请求解析域名 {domain} 返回的ip {ip}')
                    conf.insert(domain, ip)
                    return ip
                except:
                    return None

        # 不向上请求的域名
        for not_request in conf.not_request:
            if re.search(not_request, domain):
                logger.info(f'{address[0]} 请求解析域名为 {domain} 不返回结果')
                conf.log(f'{address[0]} 请求解析域名为 {domain} 不返回结果')
                return None

        # 正则匹配请求域名是否在黑名单里
        for request_blacklist in conf.request_blacklist:
            if re.search(request_blacklist, domain):
                logger.info(f'{address[0]} 请求解析域名 {domain} 被黑名单拦截')
                conf.log(f'{address[0]} 请求解析域名 {domain} 被黑名单拦截')
                return None

        # 查看域名是否在 固定域名和ip 里
        if 'domain' in conf.return_ip:
            for i in range(len(conf.return_ip['domain'])):
                if re.search(conf.return_ip['domain'][i], domain):
                    return_ip = conf.return_ip["ip"][i]['data']
                    logger.info(f'{address[0]} 请求解析域名 {domain} 返回 固定ip {return_ip}')
                    conf.log(f'{address[0]} 请求解析域名 {domain} 返回 固定ip {return_ip}')
                    return return_ip

        # 正则匹配是否是不允许访问的域名
        for not_allow in conf.not_allow:
            if re.search(not_allow, domain):
                logger.info(f'{address[0]} 请求解析域名 {domain} 是不允许访问的域名')
                conf.log(f'{address[0]} 请求解析域名 {domain} 是不允许访问的域名')
                return None

        ip = conf.dns_resolver.resolve(domain, 'A')[0].to_text()
        logger.info(f'{address[0]} 请求解析域名 {domain} ip为 {ip}')
        conf.log(f'{address[0]} 请求解析域名 {domain} ip为 {ip}')
        conf.insert(domain, ip)
        return ip

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
        # at last
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
                    # conf.log(f'{address[0]} 请求解析的消息 {message} 解析此信息失败')
                    logger.error(f'{address[0]} 请求解析的消息 {message} 解析此信息失败')
                    continue

                # 正则匹配请求 ip 是否在黑名单里
                for not_response in conf.not_response:
                    if '-' in not_response:
                        start, end = not_response.strip('^').strip('$').split('-')
                        if conf.is_ip_in_range(address[0], start, end):
                            logger.info(f'{address[0]} 请求解析域名 {domain} 该请求ip {address[0]} 被黑名单拦截')
                            conf.log(f'{address[0]} 请求解析域名 {domain} 该请求ip {address[0]} 被黑名单拦截')
                            return
                    else:
                        if re.search(not_response, address[0]):
                            logger.info(f'{address[0]} 请求解析域名 {domain} 该请求ip {address[0]} 被黑名单拦截')
                            conf.log(f'{address[0]} 请求解析域名 {domain} 该请求ip {address[0]} 被黑名单拦截')
                            return

                # 正则匹配请求 ip 是否是允许的ip
                for can_request in conf.can_request:
                    if '-' in can_request:
                        start, end = can_request.strip('^').strip('$').split('-')
                        if conf.is_ip_in_range(address[0], start, end):
                            self.dns_handler(conn, income_record, address, domain)
                            return
                    else:
                        if re.search(can_request, address[0]):
                            self.dns_handler(conn, income_record, address, domain)
                            return
                logger.info(f'{address[0]} 请求解析域名 {domain} 该请求ip {address[0]} 没有被允许')
                conf.log(f'{address[0]} 请求解析域名 {domain} 该请求ip {address[0]} 没有被允许')
            except Exception as e:
                ...


@app.route('/')
def index():
    return redirect('/index.html')


@app.route('/all')
def all_data():
    f = open('config.json', encoding='utf-8', mode='r')
    data = json.loads(f.read())
    f.close()
    return jsonify(data)


@app.route('/get_ip', methods=['POST'])
def get_ip():
    data = request.get_json()
    domain = data.get('domain', None)
    result = {'ip': ''}
    if domain:
        try:
            result['ip'] = conf.dns_resolver.resolve(domain, 'A')[0].to_text()
        except:
            pass
    return jsonify(result)


@app.route('/set_dns', methods=['POST'])
def set_dns():
    data = request.get_json()
    dns_ip = data.get('dns', None)
    result = {'code': 0}
    if dns_ip:
        try:
            conf.set_dns(dns_ip)
            return jsonify(result)
        except:
            return jsonify({'code': 2})
    return jsonify({'code': 1})


@app.route('/get_self_ip')
def get_self_ip():
    return jsonify(conf.get_ip_list())


@app.route('/update', methods=['POST'])
def update_re():
    data = request.get_json()
    for k, v in data.items():
        conf.config[k] = v
        if k == 'not_allow':
            conf.cache = {}
            conf.write_file(conf)
            conf.not_allow = [f'^{i["data"].strip()}$' for i in v if i is not None and i != '' and i['enable']]
        elif k == 'allow':
            conf.cache = {}
            conf.write_file(conf)
            conf.allow = [f'^{i["data"].strip()}$' for i in v if i is not None and i != '' and i['enable']]
        elif k == 'not_request':
            conf.cache = {}
            conf.write_file(conf)
            conf.not_request = [f'^{i["data"].strip()}$' for i in v if i is not None and i != '' and i['enable']]
        elif k == 'response_blacklist':
            conf.cache = {}
            conf.write_file(conf)
            conf.response_blacklist = [f'^{i["data"].strip()}$' for i in v if i is not None and i != '' and i['enable']]
        elif k == 'return_ip':
            conf.cache = {}
            conf.write_file(conf)
            conf.return_ip = conf.handle_ip(v)
        elif k == 'refresh_cache_time':
            conf.is_fresh = True
            schedule.clear()
            schedule_pool.submit(schedule_task)
            conf.config['refresh_cache_time'] = int(v)
            conf.refresh_cache_time = int(v)
        elif k == 'not_response':
            conf.cache = {}
            conf.write_file(conf)
            conf.not_response = [f'^{i["data"].strip()}$' for i in v if i is not None and i != '' and i['enable']]
        elif k == 'can_request':
            conf.cache = {}
            conf.write_file(conf)
            conf.can_request = [f'^{i["data"].strip()}$' for i in v if i is not None and i != '' and i['enable']]
        elif k == 'request_blacklist':
            conf.cache = {}
            conf.write_file(conf)
            conf.request_blacklist = [f'^{i["data"].strip()}$' for i in v if i is not None and i != '' and i['enable']]
        elif k == 'screen_rule':
            conf.cache = {}
            conf.write_file(conf)
            conf.screen_rule = [f'^{i["data"].strip()}$' for i in v if i is not None and i != '' and i['enable']]
        elif k == 'filter_rule':
            conf.cache = {}
            conf.write_file(conf)
            conf.filter_rule = [f'^{i["data"].strip()}$' for i in v if i is not None and i != '' and i['enable']]
        elif k == 'refresh_time':
            conf.config['refresh_time'] = int(v)
            conf.refresh_time = int(v)
        elif k == 'is_screen':
            conf.is_screen = v
        elif k == 'is_filter':
            conf.is_filter = v
        elif k == 'is_deduplicate':
            conf.is_deduplicate = v
        elif k == 'immobilization':
            conf.cache = {}
            conf.write_file(conf)
            conf.immobilization = conf.handle_ip(v)
        elif k == 'dnsservers':
            conf.cache = {}
            conf.write_file(conf)
            conf.dns_resolver.nameservers = [i["data"] for i in v if i is not None and i != '' and i['enable']]
            conf.dns_servers = [i["data"] for i in v if i is not None and i != '' and i['enable']]
        elif k == 'port':
            conf.config['port'] = int(v)
            conf.port = int(v)
        elif k == 'web_port':
            conf.config['web_port'] = int(v)
            conf.web_port = int(v)
        elif k == 'log_num':
            conf.config['log_num'] = int(v)
            conf.log_num = int(v)
    write_yaml(conf)
    return 'ok'


@app.route('/log')
def get_log():
    return jsonify(list(log_queue.queue)[::-1])


def write_yaml(conf):
    data = conf.config
    with open('config.json', encoding="utf-8", mode="w") as f:
        f.write(json.dumps(data, cls=DateEncoder, indent=1, ensure_ascii=False))


def run():
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    print('web服务端口为：' + str(conf.web_port))
    app.run(host='127.0.0.1', port=conf.web_port)


async def dns_server(loop):
    print('启动的端口为：' + str(conf.port))
    server = socketserver.ThreadingUDPServer(('0.0.0.0', conf.port), DNSServer)
    await loop.run_in_executor(None, server.serve_forever)


def get_new_cache():
    now = datetime.datetime.now()
    for domain, ip_dict in conf.cache.items():
        ip_dict['ip'] = conf.dns_resolver.resolve(domain, 'A')[0].to_text()
        ip_dict['update_time'] = now
    conf.write_file_pool.submit(conf.write_file, conf)


def schedule_task():
    get_new_cache()
    schedule.every(conf.refresh_cache_time).seconds.do(get_new_cache)
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
            if conf.is_fresh:
                conf.is_fresh = False
                break
        except:
            time.sleep(1)


if __name__ == '__main__':
    # process_queue = ProcessQueue()
    log_queue = queue.Queue()
    conf = Config()
    logger = get_myProjectLogger("dns", "log_filename", when='H', interval=1)
    pool = ThreadPoolExecutor(1)
    pool.submit(run)
    schedule_pool = ThreadPoolExecutor(1)
    schedule_pool.submit(schedule_task)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(dns_server(loop))
