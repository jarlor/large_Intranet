import tomli
import tomli_w
import os
import json
from models import FrpcConfig, Proxy

CONFIG_PATH = "/opt/frp/frpc.toml"
# 使用单独的文件存储端口映射，确保重启后不丢失
PORT_MAPPING_PATH = "/opt/frp/port_mapping.json"
PORT_MAPPING = {}

# 从文件中加载端口映射
def load_port_mapping():
    if os.path.exists(PORT_MAPPING_PATH):
        try:
            with open(PORT_MAPPING_PATH, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"加载端口映射出错: {e}")
    return {}

# 将端口映射保存到文件
def save_port_mapping(mapping):
    try:
        with open(PORT_MAPPING_PATH, 'w') as f:
            json.dump(mapping, f)
        return True
    except Exception as e:
        print(f"保存端口映射出错: {e}")
        return False

# 初始化加载端口映射
PORT_MAPPING = load_port_mapping()

def read_config():
    try:
        with open(CONFIG_PATH, "rb") as f:
            config_data = tomli.load(f)
            
        # 转换配置到我们的模型，移除WebServer相关解析
        config = {
            "serverAddr": config_data.get("serverAddr", ""),
            "serverPort": config_data.get("serverPort", 0),
            "proxies": config_data.get("proxies", [])
        }
        
        return config
    except Exception as e:
        print(f"读取配置出错: {e}")
        return None

def write_config(config_data):
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        
        with open(CONFIG_PATH, "wb") as f:
            tomli_w.dump(config_data, f)
        return True
    except Exception as e:
        print(f"写入配置出错: {e}")
        return False
        
def get_proxies():
    config = read_config()
    if config:
        proxies = config.get("proxies", [])
        # 添加状态信息，根据端口号判断是否禁用
        for proxy in proxies:
            # 确保 remotePort 是整数
            try:
                remote_port = int(proxy.get("remotePort", 0))
            except (ValueError, TypeError):
                remote_port = 0
                
            proxy["status"] = "disabled" if remote_port <= 0 else "enabled"
        return proxies
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
    
    # 同时从端口映射中删除
    global PORT_MAPPING
    if name in PORT_MAPPING:
        del PORT_MAPPING[name]
        save_port_mapping(PORT_MAPPING)
    
    return write_config(config)

def disable_proxy(name):
    global PORT_MAPPING
    config = read_config()
    if not config:
        return False
    
    # 查找并禁用代理
    for proxy in config.get("proxies", []):
        if proxy.get("name") == name:
            try:
                # 保存原始端口号用于后续恢复
                original_port = int(proxy.get("remotePort", 0))
                if original_port > 0:  # 只有当端口是有效值时才保存
                    PORT_MAPPING[name] = original_port
                    save_port_mapping(PORT_MAPPING)  # 保存到文件
                    
                    # 设置为一个无效的端口号来禁用
                    proxy["remotePort"] = -1
                    return write_config(config)
            except (ValueError, TypeError) as e:
                print(f"禁用代理时出错: {e}")
                return False
    
    return False

def enable_proxy(name):
    global PORT_MAPPING
    config = read_config()
    if not config:
        return False
    
    # 查找并启用代理
    for proxy in config.get("proxies", []):
        if proxy.get("name") == name:
            # 从映射中恢复原始端口号
            original_port = PORT_MAPPING.get(name)
            
            # 如果找到原始端口，则恢复它
            if original_port is not None:
                proxy["remotePort"] = original_port
                return write_config(config)
            else:
                # 如果没有记录，可以设置为一个默认端口（例如10000+随机数）
                # 或者返回错误，这里我们选择返回错误
                print(f"找不到代理 {name} 的原始端口")
                return False
    
    return False

