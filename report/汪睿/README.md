# 「中传放心传」总结技术报告

此报告总结了我个人在本次大作业中的主要贡献；印象深刻的一些 bug 和自己的解决方法；

## 主要贡献

### 第一阶段 架构基于网页的用户注册与登录系统

* 使用 https 绑定证书到域名而非 IP 地址 【 PKI X.509 】
    
    * 首先了解配置规范安全的 https 所需材料

        * 自签发的根证书
        * 由根证书签发的中级机构证书
        * 由中级机构证书签发的绑定域名的网站证书
    
    * 其次了解如何使用 openssl 正确规范生成以上材料

        * 参考文献 [X.509 Tutorial](https://gitee.com/c4pr1c3/ac-demo/tree/master/examples/openssl)
    
    * 编写bash脚本生成相关文件
        
        * 生成根证书私钥
        * 生成根 CA 证书签发申请文件(csr 文件)
        * 自签名根 CA 证书(crt 文件)
        * 生成中级 CA 证书私钥
        * 生成中级 CA 证书签发申请文件(csr 文件)
        * 使用根 CA 证书签发中级 CA 证书(crt 文件)
        * 生成网站服务器证书私钥(key 文件)
        * 生成网站服务器证书签发申请文件(csr 文件)
        * 使用中级 CA 证书签发网站服务器证书(crt 文件)
    
    * 材料生成完毕后，在 flask 搭建的站点配置 HTTPS 
        
        * 在浏览器中将生成的根证书设置为受信任的根证书颁发机构，将中间认证证书设置为受信任的中间颁发机构。
        * ```python
            from flask import Flask    
            app = Flask(__name__)    
            app.run('0.0.0.0', debug=True, port=8100, ssl_context=('your_path/server.crt', 'your_path/server.key'))  
          ```  

* 实现双因素认证
    
    * Email   
        
        * 选择 PassLib 库生成 OTP 
        * 使用 email 发送
        * 验证   
        * ```python
            # init.py 文件中生成TotpFactory 用于之后认证时生成Totp
            from passlib.totp import TOTP, generate_secret


            TotpFactory = TOTP.using(issuer="WhateverItIs.cuc.edu.cn", secrets={"1": generate_secret()})

            # auth.py 文件中的 login 路由
            totp=TotpFactory.new()
            data=totp.to_json()
            # totp = TOTP.from_source(data)
            # 邮箱发送随机生成的认证码
            sendMail(totp.generate().token,'','','',form.email.data,'')

            # emailway 验证函数
            match = TotpFactory.verify(token, source)
          ```  

* 安全的忘记口令 / 找回密码功能
    
    * 确认该用户存在
    * 发送邮箱验证码，验证用户实体
    * 重新设置密码对之前的密码进行覆盖


### 第二阶段 文件上传加密与数字签名系统

* 生成系统分配公私钥对，用于非对称加密
    
    * 创建的管理员使用系统公私钥对 RSA，在数据库用户表里公钥私钥一栏存路径
    *  ```python
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  
        )   

        with open(pathSK, "wb") as f:
        f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'adminadmin') #这里的 adminadmin 为加密私钥的密钥，RSA私钥安全存储
        ))

        public_key = private_key.public_key()
        with open(pathPK, "wb") as f:
        f.write(public_key.public_bytes(
         encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )) 
      ``` 
    
    * 公私钥对存储为文件存于系统文件夹里 `instance/system`  
    * 加密
    * 解密
    *  ```python
        def Encode_SK(private_bytes):
        # 使用系统公钥对私钥进行加密
        # 提取csv文件 
        file_name='System.csv'
        file_path=os.path.join(current_app.config["SYSTEM_FOLDER"], file_name)
        matrix=pd.read_csv(file_path)
        matrix=np.array(matrix)
        PK=matrix[0,0]
        PK=os.path.join(current_app.config["SYSTEM_FOLDER"], PK)
        with open(PK, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
        key_file.read()
        )
        # 字节流
        ciphertext = public_key.encrypt(
        private_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
        )
        return ciphertext

        def Decode_SK(private_bytes):
        # 使用系统私钥对私钥进行解密
        # 提取csv文件 
        file_name='System.csv'
        file_path=os.path.join(current_app.config["SYSTEM_FOLDER"], file_name)
        matrix=pd.read_csv(file_path)
        matrix=np.array(matrix)
        SK=matrix[0,1] 
        SK=os.path.join(current_app.config["SYSTEM_FOLDER"], SK)
        with open(SK, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b'adminadmin',
        )
        plaintext = private_key.decrypt(
        private_bytes,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
        )
        return plaintext
      ``` 

* 给用户分配公私钥对用于数字签名
    
    * 利用椭圆加密曲线生成公私钥对
    * 在数据库用户表里公钥私钥一栏存路径
    *  ```python
             private_key = ed25519.Ed25519PrivateKey.generate()
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            # 系统私钥加密
            new_private_bytes = Encode_SK(private_bytes)
            # loaded_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
            public_key = private_key.public_key()
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
      ``` 

* 对上传的文件求 HMAC （EtM）

    * 使用 python 自带的 hmac 库生成文件，其中所需密钥为加密文件时所使用的种子密钥，文件为字节流形式
    * 生成的 hmac 存存放于数据库文件表中 hmac 一栏中，方便后续使用与验证
    * 验证
    *  ```python
            ## 计算hmac
            private_key=Decode_SK(user.sec_key)
            symmetric_key=key
            m=get_hmac(symmetric_key,cipher_bytes)
            def get_hmac(symmetric_key,Ciphertext): #Bytes
                m=hmac.digest(symmetric_key, Ciphertext, 'sha256')
                return m

            # 客户端验证
            def Vertify_hmac(mes,symmetric_key,Ciphertext): #Bytes
            m=hmac.digest(symmetric_key, Ciphertext, 'sha256')
            try:
            hmac.compare_digest(m, mes)# Ciphertext字节流/str
            return 1
            except Exception as err:
            return 0
      ``` 

* 实现对上传文件的数字签名功能
    
    * 对上传文件的 hmac 字节流使用用户的私钥进行签名，生成 txt 签名文件
    * 文件的命名方式为`用户 id + 上传文件名 + signature` ，生成的文件存放于 `instance/download` 目录
    *  ```python
        def Signature(private_key,Ciphertext):
        loaded_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key) #已解密的私钥
        # 对加密文件的hmac进行签名,HMAC 采用EtM，使用对称加密的密钥
        signature = loaded_private_key.sign(Ciphertext)
        return signature

        def VertifySignature(public_key,signature,Ciphertext):
        try:
            public_key.verify(signature, Ciphertext)# Ciphertext字节流
            return 1
        except Exception as err:
            return 0
      ``` 
### 第三阶段 加密文件下载与解密

* 提供匿名用户加密文件关联的数字签名文件的下载
    
    * 当匿名用户点击`下载数字签名文件`时，相应的路由根据传参获得分享文件的文件 id 
    * 由文件 id 查询分享表得到加密后文件的 hmac 值和对应用户的 id
    * 再由用户 id 查询用户表得到用户私钥，使用用户私钥对 hmac 字节流进行数字签名
    * 将生成的文件返回给匿名用户
    * ```python
            from flask import Flask    
            app = Flask(__name__)    
            app.run('0.0.0.0', debug=True, port=8100, ssl_context=('your_path/server.crt', 'your_path/server.key'))  
      ```  

* 客户端对下载后的文件进行数字签名验证
    
    * 用户上传的加密文件和关联的数字签名文件存放在 `instance/download` 目录
    * 当用户点击`认证数字签名文件`时，相应的路由根据传参分析得到分享文件的 url
    * 由文件 url 查询分享表得到加密后文件的 hmac 值和对应用户的 id
    * 再由用户 id 查询用户表得到用户私钥，使用用户公钥和正确的hmac 值对数字签名文件进行签名认证
    * ```python
            from flask import Flask    
            app = Flask(__name__)    
            app.run('0.0.0.0', debug=True, port=8100, ssl_context=('your_path/server.crt', 'your_path/server.key'))  
      ```  
* 客户端对下载后的文件进行数字签名验证后对消息认证码进行验证
    
    * 使用用户上传的加密文件，加密文件使用的种子密钥和hmac 值进行消息认证码验证
    * ```python
            from flask import Flask    
            app = Flask(__name__)    
            app.run('0.0.0.0', debug=True, port=8100, ssl_context=('your_path/server.crt', 'your_path/server.key'))  
      ```  

* 提供静态文件的散列值下载，供下载文件完成后本地校验文件完整性 【 散列算法 】
  
    * 使用 python 库自带的 hashlib 库对加密后文件和原始文件求散列值，并存放于文件表中 
    * ```python
            from flask import Flask    
            app = Flask(__name__)    
            app.run('0.0.0.0', debug=True, port=8100, ssl_context=('your_path/server.crt', 'your_path/server.key'))  
      ``` 
    * 当用户点击`下载原始文件哈希值`（仅已登录用户）或`下载加密文件哈希值`时，根据相应的路由根据传参查表得到散列值文件，返回给用户
    *  ```python
            from flask import Flask    
            app = Flask(__name__)    
            app.run('0.0.0.0', debug=True, port=8100, ssl_context=('your_path/server.crt', 'your_path/server.key'))  
      ``` 

## 影响深刻的 BUG

* 如何生成树形结构的证书
  
  * 自签发根 CA 的证书
  * 根 CA 签名中间机构的证书
  * 中间 CA 签名网站服务器的证书

* 发现颁发者和使用者是同一个
        
    * 颁发者为数字签名机构
    * 使用者是持有证书的机构
    * 两者为同一个表明为自签发证书 

* 选择何种方式生成证书 
    
    * 先了解如何使用 python 语言生成以上材料
        
        * 参考文献 [X.509 Tutorial](https://cryptography.io/en/latest/x509/tutorial/) 

    * 生成树形结构后证书依旧不合格——显示中间颁发机构不能颁发证书或用作终端实体证书
    * 询问老师后，发现 x.509 证书字段非常复杂，用 python 自己编写太过于复杂且很容易出些不合格的格式，应使用 openssl 方式生成

* 此服务器无法证明它是 whateveritis.cuc.edu.cn；它的安全证书来自 *.whateveritis.cuc.edu.cn。这可能是由错误配置或者有攻击者截获你的连接而导致的。
    
    * 证书绑定了网站域名，使用该证书的网站域名必须符合 *.whateveritis.cuc.edu.cn 这种形式。
    * 域名换成这个 `https://sec.whateveritis.cuc.edu.cn:5000/`就可以正常使用。

* 配置浏览器信任证书时，发现证书文件必须是 `.crt` `crm` 格式存储，浏览器可以识别的证书文件
* 使用数字签名函数或 hmac 函数等函数时，参数需要为字节流，如何读取文件字节流
    
    * ```python
            with open(file_path, "rb") as f:
                file_bytes = f.read()
                f.close()
    ```

* 存字节流文件和字符文件时，存放文件代码不同

    * ```python
        # 字符类
        file_object = open(hashfile_path, 'w',encoding='UTF-8')
        file_object.write(hash_text)
        file_object.close()  

        # 字节流类
        file_object = open(signature_path, 'wb')
        file_object.write(m)
        file_object.close()
    ```
* flask 使用 url_for 与路由进行传参，传多个参数

    * ```python
        @auth.route('/file/<option>/' ,methods=['GET']) # {{ url_for('auth.download',option=1,file_id=file.file_id) }} 
        @login_required
        def download(option): # 上传者下载 
        # 这里 url_for 生成的 url 为 /file/1/1 如果file_id=1
        file_id = request.args["file_id"] # 解析处file_id

    ```