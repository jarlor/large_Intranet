from fastapi import FastAPI, Request, Form, HTTPException, Depends, Cookie, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Optional
import uvicorn
import os
import json
import subprocess
import secrets
from models import Proxy
import config
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
import sys
from aliyun_api import AliyunSecurityGroup
from dotenv import load_dotenv
from pathlib import Path

app = FastAPI(title="FRP Config Manager")

# 加载环境变量
env_path = Path('/opt/frp/.env')
load_dotenv(dotenv_path=env_path)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/tmp/frp_manager.log')
    ]
)
logger = logging.getLogger(__name__)

# 挂载静态文件目录
app.mount("/static", StaticFiles(directory="static"), name="static")

# 设置模板
templates = Jinja2Templates(directory="templates")

# 设置认证
security = HTTPBasic()

# 存储 session token
SESSIONS = {}

# 从环境变量中获取用户认证信息
def get_users_from_env():
    username = os.getenv('FRP_ADMIN_USER')
    password = os.getenv('FRP_ADMIN_PASSWORD')
    
    if not username or not password:
        # 如果环境变量未设置，使用默认值并记录警告
        logger.warning("环境变量中未找到用户认证信息，使用默认值")
        return {"jarlor": "123zjl.00"}
    
    return {username: password}

# 获取用户信息
USERS = get_users_from_env()

# 登录页
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": error}
    )

# 处理登录
@app.post("/login")
async def login(
    request: Request, 
    username: str = Form(...), 
    password: str = Form(...)
):
    # 验证用户名和密码
    if username in USERS and USERS[username] == password:
        # 创建会话令牌
        token = secrets.token_hex(16)
        SESSIONS[token] = username
        
        # 创建带有会话令牌的响应
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(key="session", value=token, httponly=True)
        return response
    
    # 认证失败返回登录页
    return templates.TemplateResponse(
        "login.html", 
        {"request": request, "error": "用户名或密码错误"},
        status_code=400
    )

# 退出登录
@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key="session")
    return response

# 验证会话中间件
async def verify_session(request: Request, session: str = Cookie(None)):
    if not session or session not in SESSIONS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登录或会话已过期",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return SESSIONS[session]

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    # 处理401未授权错误，重定向到登录页面
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return RedirectResponse(url="/login", status_code=303)
    # 其他错误正常处理
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": str(exc.detail)}
    )

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, username: str = Depends(verify_session)):
    proxies = config.get_proxies()
    frpc_config = config.read_config()
    
    # 提取简化的服务器配置信息，不包含webServer相关字段
    server_config = {
        "serverAddr": frpc_config.get("serverAddr", ""),
        "serverPort": frpc_config.get("serverPort", "")
    }

    # 获取 Tailscale IP 列表
    tailscale_ips = get_tailscale_ips()

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "proxies": proxies,
            "config": server_config,
            "tailscale_ips": tailscale_ips,
            "username": username,
        },
    )

# 添加保存并重启服务的路由
@app.post("/save_restart")
async def save_restart(username: str = Depends(verify_session)):
    try:
        # 重启 frpc 服务
        result = subprocess.run(
            ["sudo", "systemctl", "restart", "frpc"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        return JSONResponse({
            "success": True,
            "message": "配置已保存，服务已重启"
        })
    except subprocess.CalledProcessError as e:
        return JSONResponse({
            "success": False,
            "message": f"重启服务失败: {e.stderr}"
        }, status_code=500)
    except Exception as e:
        return JSONResponse({
            "success": False,
            "message": f"发生错误: {str(e)}"
        }, status_code=500)

@app.post("/proxy/add")
async def add_proxy(
    username: str = Depends(verify_session),
    name: str = Form(...),
    proxy_type: str = Form(...),
    local_ip: str = Form(...),
    local_port: int = Form(...),
    remote_port: int = Form(...),
):
    # 创建代理对象
    proxy = Proxy(
        name=name, type=proxy_type, localIP=local_ip, localPort=local_port, remotePort=remote_port
    )

    # 先开放阿里云安全组端口
    port_opened = AliyunSecurityGroup.open_port(
        port=remote_port, 
        protocol=proxy_type, 
        description=f"FRP代理: {name}"
    )
    
    if not port_opened:
        # 如果开放端口失败，记录但继续执行（不阻止代理创建）
        logger.warning(f"无法在阿里云安全组中开放端口 {remote_port}，但将继续创建代理")

    # 添加代理配置
    success = config.add_proxy(proxy)
    if not success:
        raise HTTPException(
            status_code=400, detail="Failed to add proxy or proxy with same name exists"
        )
    return RedirectResponse(url="/", status_code=303)

@app.post("/proxy/update/{name}")
async def update_proxy(
    name: str,
    username: str = Depends(verify_session),
    proxy_name: str = Form(...),
    proxy_type: str = Form(...),
    local_ip: str = Form(...),
    local_port: int = Form(...),
    remote_port: int = Form(...),
):
    # 获取原始代理配置，检查是否修改了端口
    original_proxy = None
    try:
        original_proxy = await get_proxy(name, username)
    except HTTPException:
        pass
    
    # 创建新代理对象
    proxy = Proxy(
        name=proxy_name,
        type=proxy_type,
        localIP=local_ip,
        localPort=local_port,
        remotePort=remote_port,
    )
    
    # 如果远程端口改变了或这是一个新代理，开放新端口
    if not original_proxy or original_proxy.get("remotePort") != remote_port:
        port_opened = AliyunSecurityGroup.open_port(
            port=remote_port, 
            protocol=proxy_type, 
            description=f"FRP代理: {proxy_name}"
        )
        
        if not port_opened:
            # 如果开放端口失败，记录但继续执行（不阻止代理更新）
            logger.warning(f"无法在阿里云安全组中开放端口 {remote_port}，但将继续更新代理")
    
    # 更新代理配置
    success = config.update_proxy(name, proxy)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to update proxy or proxy not found")
    return RedirectResponse(url="/", status_code=303)

@app.get("/proxy/delete/{name}")
async def delete_proxy(name: str, username: str = Depends(verify_session)):
    success = config.delete_proxy(name)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to delete proxy")
    return RedirectResponse(url="/", status_code=303)

@app.get("/proxy/{name}")
async def get_proxy(name: str, username: str = Depends(verify_session)):
    proxies = config.get_proxies()
    for proxy in proxies:
        if proxy.get("name") == name:
            return proxy
    raise HTTPException(status_code=404, detail="Proxy not found")

@app.post("/api/proxy/{name}/enable")
async def enable_proxy_route(name: str, username: str = Depends(verify_session)):
    # 先检查代理是否存在
    proxies = config.get_proxies()
    proxy = None
    
    for p in proxies:
        if p.get("name") == name:
            proxy = p
            # 如果代理已经启用，直接返回成功
            if p.get("status") == "enabled":
                return JSONResponse({
                    "success": True,
                    "message": f"代理 {name} 已经是启用状态"
                })
            break
    
    if not proxy:
        return JSONResponse({
            "success": False,
            "message": f"代理 {name} 不存在"
        }, status_code=404)
    
    # 获取端口号
    try:
        remote_port = int(proxy.get("remotePort"))
        if remote_port <= 0:
            # 可能是被禁用的代理，尝试从PORT_MAPPING获取原始端口
            if name in config.PORT_MAPPING:
                remote_port = int(config.PORT_MAPPING[name])
        
        if remote_port <= 0:
            return JSONResponse({
                "success": False,
                "message": "无法确定代理的远程端口"
            }, status_code=400)
            
        # 在阿里云安全组中开放端口
        protocol = proxy.get("type", "tcp")
        success = AliyunSecurityGroup.open_port(
            port=remote_port,
            protocol=protocol,
            description=f"FRP代理: {name}"
        )
        
        if not success:
            return JSONResponse({
                "success": False,
                "message": f"无法在阿里云安全组中开放端口 {remote_port}"
            }, status_code=500)
            
        # 如果代理之前是被禁用的，还需要恢复其端口配置
        if proxy.get("status") == "disabled" and name in config.PORT_MAPPING:
            config.enable_proxy(name)
            
            # 重启 frpc 服务以应用更改
            try:
                subprocess.run(["sudo", "systemctl", "restart", "frpc"], 
                              capture_output=True, text=True, check=True)
            except Exception as e:
                logger.error(f"重启frpc服务失败: {e}")
                # 即使重启失败，我们也认为端口启用成功了
        
        return JSONResponse({
            "success": True,
            "message": f"代理 {name} 的端口 {remote_port} 已成功启用"
        })
        
    except Exception as e:
        logger.error(f"启用代理 {name} 时出错: {e}")
        return JSONResponse({
            "success": False,
            "message": f"启用代理失败: {str(e)}"
        }, status_code=500)

@app.post("/api/proxy/{name}/disable")
async def disable_proxy_route(name: str, username: str = Depends(verify_session)):
    # 先检查代理是否存在
    proxies = config.get_proxies()
    proxy = None
    
    for p in proxies:
        if p.get("name") == name:
            proxy = p
            # 如果代理已经禁用，直接返回成功
            if p.get("status") == "disabled":
                return JSONResponse({
                    "success": True,
                    "message": f"代理 {name} 已经是禁用状态"
                })
            break
    
    if not proxy:
        return JSONResponse({
            "success": False,
            "message": f"代理 {name} 不存在"
        }, status_code=404)
    
    # 获取端口号并关闭
    try:
        remote_port = int(proxy.get("remotePort"))
        if remote_port <= 0:
            return JSONResponse({
                "success": False,
                "message": "代理的远程端口无效"
            }, status_code=400)
            
        # 保存原始端口号，用于后续恢复
        config.PORT_MAPPING[name] = remote_port
        config.save_port_mapping(config.PORT_MAPPING)
        
        # 在阿里云安全组中关闭端口
        protocol = proxy.get("type", "tcp")
        success = AliyunSecurityGroup.close_port(
            port=remote_port,
            protocol=protocol
        )
        
        if not success:
            return JSONResponse({
                "success": False,
                "message": f"无法在阿里云安全组中关闭端口 {remote_port}"
            }, status_code=500)
            
        # 将代理标记为禁用（修改端口为无效值）
        config.disable_proxy(name)
        
        # 重启 frpc 服务以应用更改
        try:
            subprocess.run(["sudo", "systemctl", "restart", "frpc"], 
                          capture_output=True, text=True, check=True)
        except Exception as e:
            logger.error(f"重启frpc服务失败: {e}")
            # 即使重启失败，我们也认为端口禁用成功了，因为安全组规则已更新
        
        return JSONResponse({
            "success": True,
            "message": f"代理 {name} 的端口 {remote_port} 已成功禁用"
        })
        
    except Exception as e:
        logger.error(f"禁用代理 {name} 时出错: {e}")
        return JSONResponse({
            "success": False,
            "message": f"禁用代理失败: {str(e)}"
        }, status_code=500)

def get_tailscale_ips():
    try:
        # 执行 tailscale status 命令获取节点信息，以 JSON 格式输出
        result = subprocess.run(
            ["tailscale", "status", "--json"], capture_output=True, text=True, check=True
        )

        # 解析 JSON 输出
        status_data = json.loads(result.stdout)

        # 提取 IP 和主机名
        ips = []
        for peer_id, peer_data in status_data.get("Peer", {}).items():
            # 添加每个节点的 IP 和主机名
            ips.append(
                {
                    "address": peer_data.get("TailscaleIPs", [""])[0],  # 获取第一个 IP
                    "hostname": peer_data.get("HostName", "未知主机"),
                }
            )

        return ips
    except Exception as e:
        print(f"无法获取 Tailscale IP: {e}")
        return []  # 出错时返回空列表

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=7400, reload=True)
