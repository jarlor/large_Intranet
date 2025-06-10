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

app = FastAPI(title="FRP Config Manager")

# 挂载静态文件目录
app.mount("/static", StaticFiles(directory="static"), name="static")

# 设置模板
templates = Jinja2Templates(directory="templates")

# 设置认证
security = HTTPBasic()

# 存储 session token
SESSIONS = {}

# 用户认证信息 - 实际应用中应存储在安全的配置文件或数据库中
# 密码应该进行哈希处理
USERS = {
    "jarlor": "123zjl.00"  # 示例用户名和密码，请修改为更强的密码
}

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
            "config": server_config,  # 只传递服务器基本配置
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
    proxy = Proxy(
        name=name, type=proxy_type, localIP=local_ip, localPort=local_port, remotePort=remote_port
    )

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
    proxy = Proxy(
        name=proxy_name,
        type=proxy_type,
        localIP=local_ip,
        localPort=local_port,
        remotePort=remote_port,
    )

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
