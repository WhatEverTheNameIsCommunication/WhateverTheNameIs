# 实现自分发公钥证书并实现HTTPS

## 使用方法

* 已经配置好，只需正常运行`python main.py`即可
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