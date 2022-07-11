from tkinter import E
from PIL import Image
from E import encoder
from D import decoder


def encodeImage(image,output,data): #路径/ 加密图片路径/ 嵌入数据
    image=Image.open(image)
    image=image.convert("RGB")
    output=open(output,'wb')
    iEncoder=encoder(image,80,output,'hello world')
    iEncoder.write(data,'111111')
    output.close()

def decodeImage(img,output): #加密图片路径/ 输出文件路径（所有文件输出到output.txt里）
    image=open(img,'rb')
    output=open(output,'a')
    try:
        iDecoder=decoder(image.read(),output)
        iDecoder.read('111111')
        image.close()
        output.close()
    except Exception as e:
        print('未加密')