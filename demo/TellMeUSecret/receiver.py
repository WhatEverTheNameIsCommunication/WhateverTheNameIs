from email.mime import image
from pathlib import Path
import requests
from function import decodeImage



def download_file(url): #下载文件  url：url + '/images/' + post['image'] # web server 存文件的地方
    local_filename = url.split('/')[-1]  #post['image'] xx.jpg
    with requests.get(url, stream=True) as r: #下载文件
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192): # 流下载，写入大文件时使用。
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
                    # f.flush()
    return local_filename


def get_post(url,name):
    s = requests.session()

    r = s.get(url + '/api/posts') #抓取接口值

    posts = r.json()['results'] #json解析 

    for post in posts:
        if  post['user_name']==name:
            image_file = download_file(url + '/images/' + post['image']) #获取下载的图片
            outputtext=image_file[:-4]+'.txt'
            decodeImage(image_file,outputtext)


if __name__ == '__main__':
    url = 'http://127.0.0.1:5000'
    name = 'anjing'
    # 筛选用户，只获取本用户发送的图像
    get_post(url,name)