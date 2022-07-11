from pathlib import Path
from PIL import Image
import requests
from bs4 import BeautifulSoup
from function import encodeImage,decodeImage


def send_post(username, password, text, file_path, url):
    s = requests.session() #实例化一个对象 编写request报文，自动处理cookies做状态保持

    r = s.get(url + '/auth/login') # get请求 URL 这里是到登录页面
    soup = BeautifulSoup(r.text, 'html.parser') # 爬虫页面

    csrf_token = soup.find(id="csrf_token")['value'] #找页面中 id属性为这个的值为 WTF提交表单，csrf安全提交

    params = {
        'email': username,
        'password': password,
        'csrf_token': csrf_token
    }
    r = s.post(url + '/auth/login', data=params) #发起上传请求，登录成功后会到主页面可以上传文件
    if not r.status_code == 200:
        print('Login failed.')
        return

    image = Path(file_path) # 图片所在文件夹
    from_data = {'text': text} #发送的内容
    file = {'image': (image.name, open(image, 'rb'))} #发送的图像文件

    r = s.post(url + '/api/posts', data=from_data, files=file) #上传接口
    if not r.status_code == 201:
        print('Upload post failed.')
        return


if __name__ == '__main__':
    username = ''  #已注册的用户，自己输入？
    password = ''

    text = ''
    image_file = r'' #上传文件的目录
    url = 'http://127.0.0.1:5000'

    new_image = Path(image_file).with_name('embed.jpg') #这里修改一下用户可以自己选择


    encodeImage('1.jpg','1output.jpg','hello,world!')

    # embed_watermark(image_file, 'hello,world!', str(new_image))#调用的水印函数待修改

    send_post(username, password, text, str(new_image), url)
