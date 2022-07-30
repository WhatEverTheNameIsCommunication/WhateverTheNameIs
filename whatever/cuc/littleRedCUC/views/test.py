import hashlib
import os 
if __name__ == "__main__":
    
    file_path='D:/homework-2022-s/XiaoXueQI/zcfxc/第三阶段2/whatever/cuc/instance/upload/2-we_should_all_be_feminism.doc'
    with open(file_path, "rb") as f:
                    f_bytes = f.read()
                    f.close()

    hash_text= hashlib.sha256(f_bytes)
    hash_text=hash_text.hexdigest() #加密后文件哈希值
    print(hash_text)