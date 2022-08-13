    # Dockerfile 指令
    # 基于 基础镜像
    FROM python:3.9.2

    # # 定义 元数据
    # LABEL maintainer="HashSWAP" version="1.0"

    # 将构建环境下的文件OR目录, 复制到镜像中的/code目录下, 
    ADD . /code
    
    # 设置/切换 当前工作目录 为 /code
    WORKDIR /code
    
    # # 根据需要, 定义 环境变量
    # ENV IP 192.168.70.58
    # ENV REFRESHED_AT 2022-07-20
    
    # 指定 一个OR多个 卷, 挂载到镜像 (配合后续docker cp使用)
    VOLUME ["/opt/project", "/data"]
    
    # 安装python环境支持(针对python项目)
    RUN pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple
    
    # 暴露出外界访问容器的端口
    EXPOSE 5033

    # 假设run.py是项目启动入口, 
    # ENTRYPOINT 和 CMD 指令均可用于指定容器启动时要运行的命令, 
    # 区别在于 CMD 命令可以被 docker run命令覆盖
    ENTRYPOINT ["python", "main.py"]
    CMD ["python", "main.py"]
