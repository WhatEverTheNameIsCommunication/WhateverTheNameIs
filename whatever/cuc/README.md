# 网站第一阶段使用指南

* 正常运行 `python main.py` 即可 ，如要初始化数据库请使用 `flask db init` 方法
* 注意：pass phrase 为 **passphrase**,请在自己的电脑hosts文件记录好 `127.0.0.1 sec.whateveritis.cuc.edu.cn`
    ```shell
    * Serving Flask app 'littleRedCUC.application' (lazy loading)
    * Environment: production
    WARNING: This is a development server. Do not use it in a production deployment.
    Use a production WSGI server instead.
   * Debug mode: on
    Enter PEM pass phrase:
   * Running on https://sec.whateveritis.cuc.edu.cn:5000 (Press CTRL+C to quit)
   * Restarting with stat
    111111
   * Debugger is active!
    ```
* 登录页面的 Email 指的是采用邮箱方式的双因素认证，Google 指的是采用二维码使用 google authentication app 扫码得到验证码（还未实现）
* 因为要双因素认证所以请保证你要登入的账号的**邮箱地址真实**！,如果允许时觉得麻烦可以将代码稍微修改注释。
* 如果只是单纯测试注册用户功能是否有效则邮箱地址不必真实。


# 第二阶段整合完毕（暂时
- 为测试登录方便，已注释掉双因素认证，如需验证，可找到`view.auth.login`修改注释代码块
- 进度
  - [x] 基本登录上传
  - [x] 文件加密
  - [x] 系统公私钥对
  - [ ] 文件名中文问题暂未解决
    - [ ] 如何命名能保证查找问题（限制英文or？
    - [ ] 文件名重复问题（目前没有限制机制，直接覆盖？追加数字
    - [ ] 重复文件上传问题（检测文件名直接无需上传？对比内容
  - [ ] 美观性有提高空间
    - [ ] 表格可以好看一点？
    - [ ] 显示描述文本
  - [x] 代码如废墟，需要重新优化一下
- ![](./img_README/auth-file.png)
- ![](./img_README/post_file.png)
- ![](./img_README/user.png)