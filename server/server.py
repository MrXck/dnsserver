import copy
import datetime
import json
import logging
import os
import socket
import socketserver
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from threading import Lock
from uuid import uuid4

import jwt
from flask import Flask, request, jsonify, redirect


class DateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return json.JSONEncoder.default(self, obj)


class Config:
    refresh_cache_time = 0
    fail_login_num = 0
    login_wait_second = 2
    config = {}
    lock = Lock()
    need_to_int_list = ['refresh_cache_time', 'refresh_time', 'port', 'web_port', 'log_num', 'login_wait_second', 'dns_resolve_source_port']

    def __init__(self):
        with open(os.path.join(base_dir, 'config.json'), encoding='utf-8', mode='r') as f:
            config = json.loads(f.read())
            self.config = config
        self.login_wait_second = config['login_wait_second']
        self.admin_ip = config['admin_ip']
        self.lately_login_time = datetime.datetime.now()
        self.wait_second = 1
        self.username = config['username']
        self.password = config['password']
        self.web_port = config['web_port']
        self.server = config['server']

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, item):
        return getattr(self, item)


JWT_SALT = 'fgdkljdlkfa#^&%^@$^!*^*($&@fdiskhgjfkdhfidofds*&^%&$%&'


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


app = Flask(__name__, static_folder='static', static_url_path='')


def write_yaml(conf):
    data = conf.config
    with open(os.path.join(base_dir, 'config.json'), encoding="utf-8", mode="w") as f:
        f.write(json.dumps(data, cls=DateEncoder, indent=1, ensure_ascii=False))


def update_config(data: dict, conf: Config):
    for k, v in data.items():
        conf.config[k] = v
        if k in conf.need_to_int_list:
            conf.config[k] = int(v)
        if k == 'server':
            if 'time' in v:
                conf.config[k]['time'] = int(v['time'])
                conf[k]['time'] = int(v['time'])
            if 'port' in v:
                conf.config[k]['port'] = int(v['port'])
                conf[k]['port'] = int(v['port'])


def check_token():
    authorization = request.headers.get('Authorization')
    token_result = parse_payload(authorization)
    if not token_result['status']:
        return {'data': '请登录后再进行操作'}


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
            return jsonify({'data': '登录失败'})
    finally:
        conf.lock.release()


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


@app.route('/update', methods=['POST'])
@decorator_login
def update_re():
    try:
        data = request.get_json()
    except:
        return {'data': '请正确携带参数'}
    update_config(data, conf)
    write_yaml(conf)
    return {'data': 'ok'}


@app.route('/update_can', methods=['POST'])
@decorator_login
def update_can():
    try:
        data = request.get_json()
        ip = data['ip']
        for k, v in data['data'].items():
            if k in conf.config['can'][ip]:
                conf.config['can'][ip][k] = v
        write_yaml(conf)
        return {'data': 'ok'}
    except:
        return {'data': '请正确携带参数'}


@app.route('/all')
@decorator_login
def all_data():
    f = open(os.path.join(base_dir, 'config.json'), encoding='utf-8', mode='r')
    data = json.loads(f.read())
    f.close()
    return {'data': data}


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        return try_login(data)
    except:
        return jsonify({'data': '请正确携带参数'})


@app.route('/get_config', methods=['GET'])
def get_config():
    try:
        data = {}

        ip = request.remote_addr
        if ip not in conf.config['can']:
            conf.config['can'][ip] = copy.deepcopy(config_template)
            write_yaml(conf)
            return jsonify(data)

        for k, v in conf.config['can'][ip].items():
            if v:
                data[k] = conf.config[k]
        return jsonify(data)
    except Exception as e:
        return jsonify({'data': '请正确携带参数'})


@app.route('/add_pull_ip', methods=['POST'])
@decorator_login
def add_pull_ip():
    try:
        data = request.get_json()
        ip = data['ip']

        if ip not in conf.config['can']:
            conf.config['can'][ip] = copy.deepcopy(config_template)
            write_yaml(conf)
            return {'data': 'ok'}
        else:
            return {'data': 'ip已存在'}
    except:
        return {'data': '请正确携带参数'}


@app.route('/remove_pull_ip', methods=['POST'])
@decorator_login
def remove_pull_ip():
    try:
        data = request.get_json()
        ip = data['ip']
        del conf.config['can'][ip]
        write_yaml(conf)
        return {'data': 'ok'}
    except:
        return {'data': '请正确携带参数'}


@app.route('/get_all_client', methods=['GET'])
@decorator_login
def get_all_client():
    try:
        return {'data': list(server_config.ip_socket.keys())}
    except:
        return {'data': '请正确携带参数'}


@app.route('/client/<ip>', methods=['POST'])
@decorator_login
def client(ip):
    try:
        data = request.get_json()
        method = data['method']
        string = str(uuid4())
        server_config.task_dict[string] = {
            'method': method,
            'result': None
        }
        data['random'] = string
        Server.send_message(ip, data)

        while 1:
            time.sleep(0.5)
            if server_config.task_dict[string]['result'] is not None:
                result = server_config.task_dict[string]['result']
                del server_config.task_dict[string]
                return result

    except Exception as e:
        print(e)
        return {'code': 1, 'data': '请正确携带参数'}


class ServerConfig(object):
    def __init__(self):
        self.ip_socket = {}
        self.encode = 'utf-8'
        self.task_dict = {}


class Server(socketserver.BaseRequestHandler):

    def handle(self):
        conn = self.request

        while True:
            try:
                # 在这里处理连接断开时的逻辑
                server_config.ip_socket[self.client_address[0]] = self.request
                length = conn.recv(4)
                length = struct.unpack('>I', length)[0]
                data = conn.recv(length)
                data = json.loads(data)
                server_config.task_dict[data['random']]['result'] = data
            except ConnectionResetError:
                # 连接断开时的操作
                del server_config.ip_socket[self.client_address[0]]

    @staticmethod
    def send_message(ip, data):
        try:
            data = f'{json.dumps(data)}'.encode(server_config.encode)
            data_len = struct.pack('>I', len(data))
            server_config.ip_socket[ip].send(data_len + data)
        except:
            del server_config.ip_socket[ip]


def start_socket():
    serve = socketserver.ThreadingTCPServer(('0.0.0.0', conf.server['port'] + 1), Server)
    serve.serve_forever()


if __name__ == '__main__':
    base_dir = os.path.dirname(sys.argv[0])
    conf = Config()
    config_template = {
        "admin_ip": False,
        "allow": False,
        "can_request": False,
        "dangerous_domain": False,
        "white_domain": False,
        "dnsservers": False,
        "elk": False,
        "filter_rule": False,
        "immobilization": False,
        "is_deduplicate": False,
        "is_filter": False,
        "is_screen": False,
        "log_num": False,
        "login_wait_second": False,
        "not_allow": False,
        "not_request": False,
        "not_response": False,
        "password": False,
        "port": False,
        "refresh_cache_time": False,
        "refresh_time": False,
        "request_blacklist": False,
        "response_blacklist": False,
        "return_ip": False,
        "screen_rule": False,
        "server": False,
        "username": False,
        "dangerous_domain_return_ip": False,
        "dns_resolve_source_port": False,
        "web_port": False
    }
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    print('web服务端口为：' + str(conf.web_port))

    server_config = ServerConfig()
    socket_pool = ThreadPoolExecutor(1)
    socket_pool.submit(start_socket)

    try:
        app.run(host='0.0.0.0', port=conf.web_port, ssl_context=('server.crt', 'server.key'))
    except Exception as e:
        print(e)
