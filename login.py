import base64,hashlib,json
import time
from flask import Flask,request,jsonify,redirect

app = Flask(__name__)

# 配置类
class Config(object):
    # sha256 的签名秘钥
    SECRET = 'erkjewrjlewrjklecxidugofig'
    # JWT头，存放加密方式
    HEADER = {
        "typ": "JWT",
        "alg": "HS256"
    }

    # jwt的过期时间
    JWT_OUTTIME = 60*60*7
    DEBUT = True


app.config.from_object(Config)

# 登录
@app.route('/login',methods=['POST'])
def login():
    if request.method== 'GET':
        return '请输入登录信息'
    if  request.method == 'POST':
        # 将用户信息转化为json
        data = json.loads(request.data)
        username = data.get('username')
        pwd = data.get('pwd')
        # 检验数据完整
        if not all([username,pwd]):
            return jsonify({"status":205,"msg":"信息不全"})
        print(username,pwd)
        if username == 'zhangsan' and pwd =='123':
            header = base64.b64encode(str(Config.HEADER).encode('utf-8'))
            # 返货的用户信息
            userinfo = {
                "uid": "1",
                "name": "zhangsan",
                "admin": "true",
                "iat":time.time() #
            }
            payload = base64.b64encode(json.dumps(userinfo).encode('utf-8'))
            header_payload = header + b"." +payload
            # 加密header_payload
            s256=hashlib.sha256(Config.SECRET.encode('utf-8'))
            s256.update(header_payload)
            signature = s256.hexdigest().encode('utf-8')

            jwt = header_payload + b'.' + signature
            # 构造返回字典
            data = {}
            data["jwt"] = jwt.decode('utf-8')
            data["msg"] = "登录成功"
            data["status"] = 200
            return jsonify(data)
    return '登录失败'


# 主页用于验证JWT登录
@app.route('/index',methods=['GET','POST'])
def index():
    # 从request中取出用户id，从而确认用户的身份
    print(request.userid)
    return 'index'


# 登录检验
@app.before_request
def process_request(*args,**kwargs):
    if request.path == '/login':
        return None
    # 从headers中取得token
    jwt = request.headers.get('token')
    if jwt:
        # 将token分割成 header_payload 和 signature
        header_payload,signature = jwt.rsplit('.',1)
        # 对header_payload 进行验签,
        s256 = hashlib.sha256(Config.SECRET.encode('utf-8'))
        s256.update(header_payload.encode('utf-8'))
        # 相同则验签成功
        if signature == s256.hexdigest():
            # 分别取出header,payload
            header,payload = header_payload.split('.')
            # 将二进制的userinfo转化为json_str字符串
            userinfo_bytes = base64.b64decode(payload.encode('utf-8'))
            # 将 json转化成字典
            userinfo = json.loads(userinfo_bytes.decode('utf-8'))
            # 获取jwt创建时间
            create_time = userinfo.get('iat')
            if create_time is None:
                return '没有token创建时间'
            # 检验是否过期
            if time.time() - create_time > Config.JWT_OUTTIME:
                return 'token已过期'

            # 将用户信息放入request，这里的request__setattr__已经被改写
            # 成为了类似{'线程id':'data'}的类型，每个线程只会取出自己对应的值
            request.userid = userinfo.get('uid')
            return None
        return '404 token已经被修改'
    return redirect('/login')


if __name__ == '__main__':
    app.run()
