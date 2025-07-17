import tomli
import tomli_w
import os
import json
from models import FrpcConfig, Proxy
import logging
import subprocess
import tempfile

logger = logging.getLogger(__name__)

CONFIG_PATH = "/opt/frp/frpc.toml"
# 使用单独的文件存储端口映射，确保重启后不丢失
PORT_MAPPING_PATH = "/opt/frp/port_mapping.json"
PORT_MAPPING = {}

# 远程服务器配置
REMOTE_SERVER = "100.66.95.34"
REMOTE_CONFIG_PATH = "/opt/frpc/frpc.toml"
REMOTE_PORT_MAPPING_PATH = "/opt/frpc/port_mapping.json"

# 从文件中加载端口映射
def load_port_mapping():
    if os.path.exists(PORT_MAPPING_PATH):
        try:
            with open(PORT_MAPPING_PATH, 'r') as f:
                mapping = json.load(f)
                # 确保所有键和值都是正确的类型
                result = {}
                for k, v in mapping.items():
                    try:
                        result[k] = int(v)
                    except (ValueError, TypeError):
                        pass
                return result
        except Exception as e:
            logger.error(f"加载端口映射出错: {e}")
    return {}

# 将端口映射保存到文件
def save_port_mapping(mapping):
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(PORT_MAPPING_PATH), exist_ok=True)
        with open(PORT_MAPPING_PATH, 'w') as f:
            json.dump(mapping, f)
        return True
    except Exception as e:
        logger.error(f"保存端口映射出错: {e}")
        return False

# 初始化加载端口映射
PORT_MAPPING = load_port_mapping()

def execute_remote_command(command, capture_output=True):
    """执行远程命令"""
    try:
        full_command = ["ssh", REMOTE_SERVER, command]
        result = subprocess.run(
            full_command,
            capture_output=capture_output,
            text=True,
            check=True
        )
        return result.stdout if capture_output else True
    except subprocess.CalledProcessError as e:
        logger.error(f"远程命令执行失败: {e}")
        return None

def read_remote_config():
    """读取远程服务器配置"""
    try:
        # 使用临时文件
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as temp_file:
            temp_path = temp_file.name
        
        # 从远程服务器下载配置文件
        scp_command = ["scp", f"{REMOTE_SERVER}:{REMOTE_CONFIG_PATH}", temp_path]
        result = subprocess.run(scp_command, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"下载远程配置文件失败: {result.stderr}")
            # 清理临时文件
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            return None
        
        # 检查文件是否为空
        if os.path.getsize(temp_path) == 0:
            logger.error("远程配置文件为空")
            os.unlink(temp_path)
            return None
        
        # 读取配置文件
        with open(temp_path, "rb") as f:
            config_data = tomli.load(f)
        
        # 清理临时文件
        os.unlink(temp_path)
        
        # 转换配置到我们的模型
        config = {
            "serverAddr": config_data.get("serverAddr", ""),
            "serverPort": config_data.get("serverPort", 0),
            "proxies": config_data.get("proxies", [])
        }
        
        return config
    except Exception as e:
        logger.error(f"读取远程配置出错: {e}")
        return None

def write_remote_config(config_data):
    """写入远程服务器配置"""
    try:
        # 使用临时文件
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as temp_file:
            temp_path = temp_file.name
            tomli_w.dump(config_data, temp_file)
        
        # 确保远程目录存在
        execute_remote_command(f"sudo mkdir -p {os.path.dirname(REMOTE_CONFIG_PATH)}")
        
        # 上传配置文件到远程服务器
        scp_command = ["scp", temp_path, f"{REMOTE_SERVER}:{REMOTE_CONFIG_PATH}"]
        result = subprocess.run(scp_command, capture_output=True, text=True)
        
        # 清理临时文件
        os.unlink(temp_path)
        
        if result.returncode != 0:
            logger.error(f"上传远程配置文件失败: {result.stderr}")
            return False
        
        return True
    except Exception as e:
        logger.error(f"写入远程配置出错: {e}")
        return False

def load_remote_port_mapping():
    """从远程服务器加载端口映射"""
    try:
        # 检查远程文件是否存在
        check_result = execute_remote_command(f"test -f {REMOTE_PORT_MAPPING_PATH}")
        if check_result is None:
            return {}
        
        # 使用临时文件
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            temp_path = temp_file.name
        
        # 从远程服务器下载端口映射文件
        scp_command = ["scp", f"{REMOTE_SERVER}:{REMOTE_PORT_MAPPING_PATH}", temp_path]
        result = subprocess.run(scp_command, capture_output=True, text=True)
        
        if result.returncode != 0:
            os.unlink(temp_path)
            return {}
        
        # 读取映射文件
        with open(temp_path, 'r') as f:
            mapping = json.load(f)
        
        # 清理临时文件
        os.unlink(temp_path)
        
        # 确保所有键和值都是正确的类型
        result = {}
        for k, v in mapping.items():
            try:
                result[k] = int(v)
            except (ValueError, TypeError):
                pass
        return result
    except Exception as e:
        logger.error(f"加载远程端口映射出错: {e}")
        return {}

def save_remote_port_mapping(mapping):
    """将端口映射保存到远程服务器"""
    try:
        # 使用临时文件
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            temp_path = temp_file.name
            json.dump(mapping, temp_file)
        
        # 确保远程目录存在
        execute_remote_command(f"sudo mkdir -p {os.path.dirname(REMOTE_PORT_MAPPING_PATH)}")
        
        # 上传映射文件到远程服务器
        scp_command = ["scp", temp_path, f"{REMOTE_SERVER}:{REMOTE_PORT_MAPPING_PATH}"]
        result = subprocess.run(scp_command, capture_output=True, text=True)
        
        # 清理临时文件
        os.unlink(temp_path)
        
        return result.returncode == 0
    except Exception as e:
        logger.error(f"保存远程端口映射出错: {e}")
        return False

def restart_remote_frpc():
    """重启远程服务器的 frpc 服务"""
    try:
        result = execute_remote_command("sudo systemctl restart frpc")
        return result is not None
    except Exception as e:
        logger.error(f"重启远程 frpc 服务失败: {e}")
        return False

# 修改现有函数，添加服务器选择参数
def read_config(server="local"):
    if server == "remote":
        return read_remote_config()
    try:
        # 检查本地配置文件是否存在
        if not os.path.exists(CONFIG_PATH):
            logger.error(f"本地配置文件不存在: {CONFIG_PATH}")
            return None
        
        # 检查文件是否为空
        if os.path.getsize(CONFIG_PATH) == 0:
            logger.error(f"本地配置文件为空: {CONFIG_PATH}")
            return None
        
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
        logger.error(f"读取本地配置出错: {e}")
        return None

def write_config(config_data, server="local"):
    if server == "remote":
        return write_remote_config(config_data)
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        
        with open(CONFIG_PATH, "wb") as f:
            tomli_w.dump(config_data, f)
        return True
    except Exception as e:
        print(f"写入配置出错: {e}")
        return False
        
def get_proxies(server="local"):
    config = read_config(server)
    if config is None:
        logger.warning(f"无法读取 {server} 服务器配置，返回空代理列表")
        return []
    
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

def add_proxy(proxy, server="local"):
    config = read_config(server)
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
    
    return write_config(config, server)

def update_proxy(name, proxy, server="local"):
    config = read_config(server)
    if not config:
        return False
        
    # 查找并更新代理
    for i, existing_proxy in enumerate(config.get("proxies", [])):
        if existing_proxy.get("name") == name:
            config["proxies"][i] = proxy.dict()
            return write_config(config, server)
    
    return False
    
def delete_proxy(name, server="local"):
    config = read_config(server)
    if not config:
        return False
    
    # 过滤掉要删除的代理
    config["proxies"] = [p for p in config.get("proxies", []) if p.get("name") != name]
    
    # 同时从端口映射中删除
    global PORT_MAPPING
    if server == "remote":
        remote_mapping = load_remote_port_mapping()
        if name in remote_mapping:
            del remote_mapping[name]
            save_remote_port_mapping(remote_mapping)
    else:
        if name in PORT_MAPPING:
            del PORT_MAPPING[name]
            save_port_mapping(PORT_MAPPING)
    
    return write_config(config, server)

def disable_proxy(name, server="local"):
    global PORT_MAPPING
    config = read_config(server)
    if not config:
        return False
    
    # 查找并禁用代理
    for proxy in config.get("proxies", []):
        if proxy.get("name") == name:
            try:
                # 保存原始端口号用于后续恢复
                original_port = int(proxy.get("remotePort", 0))
                if original_port > 0:  # 只有当端口是有效值时才保存
                    if server == "remote":
                        remote_mapping = load_remote_port_mapping()
                        remote_mapping[name] = original_port
                        save_remote_port_mapping(remote_mapping)
                    else:
                        PORT_MAPPING[name] = original_port
                        save_port_mapping(PORT_MAPPING)
                    
                    # 设置为一个无效的端口号来禁用
                    proxy["remotePort"] = -1
                    return write_config(config, server)
            except (ValueError, TypeError) as e:
                logger.error(f"禁用代理时出错: {e}")
                return False
    
    return False

def enable_proxy(name, server="local"):
    global PORT_MAPPING
    config = read_config(server)
    if not config:
        return False
    
    # 查找并启用代理
    for proxy in config.get("proxies", []):
        if proxy.get("name") == name:
            # 从映射中恢复原始端口号
            if server == "remote":
                remote_mapping = load_remote_port_mapping()
                original_port = remote_mapping.get(name)
            else:
                original_port = PORT_MAPPING.get(name)
            
            # 如果找到原始端口，则恢复它
            if original_port is not None:
                proxy["remotePort"] = original_port
                return write_config(config, server)
            else:
                logger.error(f"找不到代理 {name} 的原始端口")
                return False
    
    return False

