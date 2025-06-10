import tomli
import tomli_w
import os
from models import FrpcConfig, Proxy

CONFIG_PATH = "/opt/frp/frpc.toml"

def read_config():
    try:
        with open(CONFIG_PATH, "rb") as f:
            config_data = tomli.load(f)
            
        # 转换配置到我们的模型
        # 处理扁平化的webServer配置
        config = {
            "serverAddr": config_data.get("serverAddr", ""),
            "serverPort": config_data.get("serverPort", 0),
            "webServer.addr": config_data.get("webServer.addr", ""),
            "webServer.port": config_data.get("webServer.port", 0),
            "webServer.user": config_data.get("webServer.user", ""),
            "webServer.password": config_data.get("webServer.password", ""),
            "proxies": config_data.get("proxies", [])
        }
        
        return config
    except Exception as e:
        print(f"Error reading config: {e}")
        return None

def write_config(config_data):
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        
        with open(CONFIG_PATH, "wb") as f:
            tomli_w.dump(config_data, f)
        return True
    except Exception as e:
        print(f"Error writing config: {e}")
        return False
        
def get_proxies():
    config = read_config()
    if config:
        return config.get("proxies", [])
    return []

def add_proxy(proxy):
    config = read_config()
    if not config:
        return False
        
    # 检查是否有重名的代理
    for existing_proxy in config.get("proxies", []):
        if existing_proxy.get("name") == proxy.name:
            return False
            
    # 添加新代理
    if "proxies" not in config:
        config["proxies"] = []
    config["proxies"].append(proxy.dict())
    
    return write_config(config)
    
def update_proxy(name, proxy):
    config = read_config()
    if not config:
        return False
        
    # 查找并更新代理
    for i, existing_proxy in enumerate(config.get("proxies", [])):
        if existing_proxy.get("name") == name:
            config["proxies"][i] = proxy.dict()
            return write_config(config)
    
    return False
    
def delete_proxy(name):
    config = read_config()
    if not config:
        return False
    
    # 过滤掉要删除的代理
    config["proxies"] = [p for p in config.get("proxies", []) if p.get("name") != name]
    
    return write_config(config)

