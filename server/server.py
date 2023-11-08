import datetime
import json
import logging
import os
import sys
from functools import wraps
from threading import Lock

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
    need_to_int_list = ['refresh_cache_time', 'refresh_time', 'port', 'web_port', 'log_num', 'login_wait_second']

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
        return '请正确携带参数'
    update_config(data, conf)
    write_yaml(conf)
    return {'data': 'ok'}


@app.route('/update_can', methods=['POST'])
@decorator_login
def update_can():
    try:
        data = request.get_json()
    except:
        return '请正确携带参数'
    for k, v in data.items():
        if k in conf.config['can']:
            conf.config['can'][k] = v
    write_yaml(conf)
    return {'data': 'ok'}


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
        for k, v in conf.config['can'].items():
            if v:
                data[k] = conf.config[k]
        return jsonify(data)
    except Exception as e:
        return jsonify({'data': '请正确携带参数'})


if __name__ == '__main__':
    base_dir = os.path.dirname(sys.argv[0])
    conf = Config()
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    print('web服务端口为：' + str(conf.web_port))
    try:
        app.run(host='0.0.0.0', port=conf.web_port, ssl_context=('server.crt', 'server.key'))
    except Exception as e:
        print(e)
