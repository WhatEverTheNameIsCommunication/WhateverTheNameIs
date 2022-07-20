# 网站第一阶段使用指南

* 正常运行 `python main.py` 即可 ，如要初始化数据库请使用 `flask db init` 方法
* 注意：pass phrase 为 **passphrase**,请在自己的电脑hosts文件记录好 `127.0.0.1 WhateverItIs.cuc.edu.cn`
    ```shell
    * Serving Flask app 'littleRedCUC.application' (lazy loading)
    * Environment: production
    WARNING: This is a development server. Do not use it in a production deployment.
    Use a production WSGI server instead.
   * Debug mode: on
    Enter PEM pass phrase:
   * Running on https://WhateverItIs.cuc.edu.cn:5000 (Press CTRL+C to quit)
   * Restarting with stat
    111111
   * Debugger is active!
    ```
* 登录页面的 Email 指的是采用邮箱方式的双因素认证，Google 指的是采用二维码使用 google authentication app 扫码得到验证码（还未实现）
* 因为要双因素认证所以请保证你要登入的账号的**邮箱地址真实**！
* 如果只是单纯测试注册用户功能是否有效则邮箱地址不必真实。