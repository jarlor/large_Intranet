import os
from alibabacloud_ecs20140526.client import Client as Ecs20140526Client
from alibabacloud_credentials.client import Client as CredentialClient
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_ecs20140526 import models as ecs_20140526_models
from alibabacloud_tea_util import models as util_models
from alibabacloud_tea_util.client import Client as UtilClient

import logging
logger = logging.getLogger(__name__)

class AliyunSecurityGroup:
    @staticmethod
    def create_client() -> Ecs20140526Client:
        """
        使用凭据初始化账号Client
        @return: Client
        """
        try:
            credential = CredentialClient()
            config = open_api_models.Config(
                credential=credential
            )
            # Endpoint 设置
            config.endpoint = 'ecs.cn-beijing.aliyuncs.com'
            return Ecs20140526Client(config)
        except Exception as e:
            logger.error(f"创建阿里云客户端失败: {e}")
            return None

    @staticmethod
    def open_port(port, protocol='TCP', description=None):
        """
        在安全组中开放指定端口
        @param port: 端口号
        @param protocol: 协议，默认TCP
        @param description: 描述信息
        @return: 是否成功
        """
        # 安全检查
        if not isinstance(port, int) or port <= 0 or port > 65535:
            logger.error(f"无效的端口号: {port}")
            return False
            
        try:
            client = AliyunSecurityGroup.create_client()
            if not client:
                return False
                
            # 设置描述信息
            if not description:
                description = f'FRP代理端口 {port}'
                
            # 端口范围
            port_range = f"{port}/{port}"
            
            # 创建权限规则
            permission = ecs_20140526_models.AuthorizeSecurityGroupRequestPermissions(
                policy='accept',
                priority='1',  # 优先级，1-100，数字越小优先级越高
                ip_protocol=protocol.upper(),  # 转换为大写
                port_range=port_range,
                description=description,
                source_cidr_ip='0.0.0.0/0'  # 允许所有IP访问
            )
            
            # 创建请求
            request = ecs_20140526_models.AuthorizeSecurityGroupRequest(
                region_id='cn-beijing',  # 地区ID
                security_group_id='sg-2ze22mgbvzziua91enkk',  # 安全组ID
                permissions=[permission]
            )
            
            runtime = util_models.RuntimeOptions()
            
            # 发送请求
            client.authorize_security_group_with_options(request, runtime)
            
            logger.info(f"成功开放端口 {port}/{protocol}")
            return True
            
        except Exception as e:
            logger.error(f"开放端口 {port} 失败: {e}")
            if hasattr(e, 'message'):
                logger.error(f"错误信息: {e.message}")
            if hasattr(e, 'data') and e.data.get("Recommend"):
                logger.error(f"诊断信息: {e.data.get('Recommend')}")
            return False