from PyInstaller.__main__ import run

if __name__ == '__main__':
    opts = [
        'dns_server_socketserver_with_asyncio.py',  # 主程序文件
        '-n dns',  # 可执行文件名称
        '-F',  # 打包单文件
        # '-w', #是否以控制台黑窗口运行
        # r'--icon=E:/图标/leaves_16px_1218386_easyicon.net.ico',  # 可执行程序图标
        '-y',
        '--clean',
        '--workpath=build',
        '--add-data=static;static',  # 打包包含的静态资源
        '--add-data=server.crt;.',  # 打包包含的静态资源
        '--add-data=server.key;.',  # 打包包含的静态资源
        '--distpath=build',
        '--specpath=./'
    ]

    run(opts)
