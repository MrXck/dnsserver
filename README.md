## DNSServer

代码使用 python3.8版本开发
支持以下功能：

1. 配置ip允许/禁止访问此服务器
   1. 支持配置ip范围
   2. 会使用正则对输入的值进行校验
2. 配置上级dns服务器
3. 配置指定域名返回空值(支持正则)
4. 配置指定域名不允许访问(支持正则)
5. 配置域名直接返回指定ip(支持正则)
6. 对域名解析后的ip进行缓存，会定期(可自行配置时间)刷新缓存
7. 可一键修改服务器的dns配置(需要以管理员身份运行)
8. 支持日志
9. 支持对配置的dns服务器进行测试

需要向项目目录下放置 server.crt 和 server.key 证书 或者 在代码的 874 行去掉 ssl_context=('server.crt', 'server.key')
由于技术有限无法做出客户端所以使用 vue + elementUI 网页来作为配置
运行后浏览器打开 https://127.0.0.1:5000 就可以配置了
