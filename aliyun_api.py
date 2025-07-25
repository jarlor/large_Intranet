import os
from alibabacloud_ecs20140526.client import Client as Ecs20140526Client
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_ecs20140526 import models as ecs_20140526_models
from alibabacloud_tea_util import models as util_models
from alibabacloud_tea_util.client import Client as UtilClient

import logging

logger = logging.getLogger(__name__)


class AliyunSecurityGroup:
    # 从环境变量中获取配置
    SECURITY_GROUP_ID = os.getenv("ALIYUN_SECURITY_GROUP_ID", "sg-2ze22mgbvzziua91enkk")
    REGION_ID = os.getenv("ALIYUN_REGION_ID", "cn-beijing")
    ENDPOINT = os.getenv("ALIYUN_API_ENDPOINT", "ecs.cn-beijing.aliyuncs.com")

    @staticmethod
    def create_client() -> Ecs20140526Client:
        """
        使用环境变量中的AccessKey初始化账号Client
        @return: Client
        """
        try:
            # 从环境变量获取AccessKey
            access_key_id = os.getenv("ALIYUN_ACCESS_KEY_ID")
            access_key_secret = os.getenv("ALIYUN_ACCESS_KEY_SECRET")

            # 验证关键凭据是否存在
            if not access_key_id or not access_key_secret:
                logger.error("环境变量中未找到阿里云AccessKey，请检查.env文件配置")
                return None

            # 使用AccessKey和Secret创建配置
            config = open_api_models.Config(
                access_key_id=access_key_id, access_key_secret=access_key_secret
            )
            # Endpoint 设置
            config.endpoint = AliyunSecurityGroup.ENDPOINT
            return Ecs20140526Client(config)
        except Exception as e:
            logger.error(f"创建阿里云客户端失败: {e}")
            return None

    @staticmethod
    def check_port_status(port, protocol="TCP"):
        """
        检查指定端口在安全组中的状态
        @param port: 端口号
        @param protocol: 协议，默认TCP
        @return: (bool, str) - (是否已开放, 详细信息)
        """
        # 安全检查
        if not isinstance(port, int) or port <= 0 or port > 65535:
            logger.error(f"无效的端口号: {port}")
            return False, "无效的端口号"

        try:
            client = AliyunSecurityGroup.create_client()
            if not client:
                return False, "无法创建阿里云客户端"

            # 创建查询安全组规则的请求
            request = ecs_20140526_models.DescribeSecurityGroupAttributeRequest(
                region_id=AliyunSecurityGroup.REGION_ID,
                security_group_id=AliyunSecurityGroup.SECURITY_GROUP_ID,
                nic_type="internet"  # 查询公网规则
            )

            runtime = util_models.RuntimeOptions()

            # 发送请求
            response = client.describe_security_group_attribute_with_options(request, runtime)
            
            # 检查端口是否在规则中
            port_range = f"{port}/{port}"
            protocol_upper = protocol.upper()
            
            # 检查入方向规则
            for permission in response.body.permissions.permission:
                if permission.port_range == port_range and permission.ip_protocol == protocol_upper:
                    logger.info(f"端口 {port}/{protocol} 已在安全组中开放")
                    return True, f"端口 {port}/{protocol} 已在安全组中开放"
            
            logger.info(f"端口 {port}/{protocol} 未在安全组中开放")
            return False, f"端口 {port}/{protocol} 未在安全组中开放"

        except Exception as e:
            error_msg = f"检查端口 {port} 状态失败: {e}"
            logger.error(error_msg)
            if hasattr(e, "message"):
                logger.error(f"错误信息: {e.message}")
            if hasattr(e, "data") and e.data.get("Recommend"):
                logger.error(f"诊断信息: {e.data.get('Recommend')}")
            return False, error_msg

    @staticmethod
    def open_port(port, protocol="TCP", description=None):
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
            # 先检查端口状态
            is_open, msg = AliyunSecurityGroup.check_port_status(port, protocol)
            if is_open:
                logger.info(f"端口 {port}/{protocol} 已经开放，无需操作")
                return True
                
            client = AliyunSecurityGroup.create_client()
            if not client:
                return False

            # 设置描述信息
            if not description:
                description = f"FRP代理端口 {port}"

            # 端口范围
            port_range = f"{port}/{port}"

            # 创建权限规则
            permission = ecs_20140526_models.AuthorizeSecurityGroupRequestPermissions(
                policy="accept",
                priority="1",  # 优先级，1-100，数字越小优先级越高
                ip_protocol=protocol.upper(),  # 转换为大写
                port_range=port_range,
                description=description,
                source_cidr_ip="0.0.0.0/0",  # 允许所有IP访问
            )

            # 创建请求
            request = ecs_20140526_models.AuthorizeSecurityGroupRequest(
                region_id=AliyunSecurityGroup.REGION_ID,
                security_group_id=AliyunSecurityGroup.SECURITY_GROUP_ID,
                permissions=[permission],
            )

            runtime = util_models.RuntimeOptions()

            # 发送请求
            client.authorize_security_group_with_options(request, runtime)

            logger.info(f"成功开放端口 {port}/{protocol}")
            return True

        except Exception as e:
            logger.error(f"开放端口 {port} 失败: {e}")
            if hasattr(e, "message"):
                logger.error(f"错误信息: {e.message}")
            if hasattr(e, "data") and e.data.get("Recommend"):
                logger.error(f"诊断信息: {e.data.get('Recommend')}")
            return False

    @staticmethod
    def close_port(port, protocol="TCP"):
        """
        在安全组中关闭指定端口
        @param port: 端口号
        @param protocol: 协议，默认TCP
        @return: 是否成功
        """
        # 安全检查
        if not isinstance(port, int) or port <= 0 or port > 65535:
            logger.error(f"无效的端口号: {port}")
            return False

        try:
            # 先检查端口状态
            is_open, msg = AliyunSecurityGroup.check_port_status(port, protocol)
            if not is_open:
                logger.info(f"端口 {port}/{protocol} 已经关闭，无需操作")
                return True
                
            client = AliyunSecurityGroup.create_client()
            if not client:
                return False

            # 端口范围
            port_range = f"{port}/{port}"

            # 创建权限规则
            permission = ecs_20140526_models.RevokeSecurityGroupRequestPermissions(
                policy="accept",
                priority="1",
                ip_protocol=protocol.upper(),
                port_range=port_range,
                source_cidr_ip="0.0.0.0/0",
            )

            # 创建请求
            request = ecs_20140526_models.RevokeSecurityGroupRequest(
                region_id=AliyunSecurityGroup.REGION_ID,
                security_group_id=AliyunSecurityGroup.SECURITY_GROUP_ID,
                permissions=[permission],
            )

            runtime = util_models.RuntimeOptions()

            # 发送请求
            client.revoke_security_group_with_options(request, runtime)

            logger.info(f"成功关闭端口 {port}/{protocol}")
            return True

        except Exception as e:
            logger.error(f"关闭端口 {port} 失败: {e}")
            if hasattr(e, "message"):
                logger.error(f"错误信息: {e.message}")
            if hasattr(e, "data") and e.data.get("Recommend"):
                logger.error(f"诊断信息: {e.data.get('Recommend')}")
            return False
