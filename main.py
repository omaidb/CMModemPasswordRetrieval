import os  # 导入操作系统相关模块
import re  # 导入正则表达式模块
import subprocess  # 导入子进程模块，用于执行系统命令
# import telnetlib  # 导入Telnet库，用于Telnet连接
import Exscript.protocols.telnetlib as telnetlib  # 导入Exscript库中的Telnet模块，用于Telnet连接
import time  # 导入时间模块，用于延时操作

import requests  # 导入requests库，用于HTTP请求
from loguru import logger  # 导入loguru库，用于日志记录

def clear_console():
    # 清空控制台
    rows, columns = os.get_terminal_size()  # 获取终端的行数和列数
    print("\n" * rows, end="")  # 打印空行以清空终端内容


def obtain_value_from_text(text):
    # 从文本中提取特定的值
    lines_to_return = []  # 初始化返回的行列表

    if text is None:  # 如果输入文本为空
        return lines_to_return  # 返回空列表

    # 正则表达式匹配以 "get success!value=" 开头的行
    pattern = re.compile(r'^get success!value=.*$')

    # 将输入的文本按行处理
    for line in text.splitlines():
        line = line.strip()  # 去除行首尾的空格
        if line and pattern.match(line):  # 如果行不为空且匹配正则表达式
            lines_to_return.append(line)  # 添加到返回列表中

    return lines_to_return  # 返回匹配的行列表


class ModemManager:
    def __init__(self):
        # 初始化Modem管理器
        self.host = ""  # 主机地址
        self.port = 23  # Telnet端口号
        self.mac_address = ""  # MAC地址
        self.method = ""  # Telnet启用方法

    def set_host(self):
        # 设置主机地址
        host = input("Please enter the IP address of the modem (default:192.168.1.1): ") or "192.168.1.1"  # 获取用户输入的IP地址，默认为192.168.1.1
        if not isinstance(host, str):  # 检查输入是否为字符串
            raise TypeError("Host address must be a string.")  # 抛出类型错误
        if not host:  # 检查输入是否为空
            raise ValueError("Host address must not be empty.")  # 抛出值错误
        # 使用正则表达式验证IP地址格式
        if not re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", host):
            raise ValueError("Invalid host address.")  # 抛出值错误
        self.host = host  # 设置主机地址
        logger.info(f"Host set to: {self.host}")  # 记录日志
        return self.host  # 返回主机地址

    def get_mac_address(self):
        # 获取MAC地址
        try:
            # 执行arp命令获取ARP表
            arp_result = subprocess.check_output("arp -a", shell=True).decode('utf-8')
        except UnicodeDecodeError:
            # 如果解码失败，尝试使用gbk解码
            arp_result = subprocess.check_output("arp -a", shell=True).decode('gbk')
        except Exception as e:
            # 捕获其他异常并记录日志
            logger.error(f"Please Check your host address or Send the following error to the author:\r\n{e}")
            exit(0)  # 退出程序
        if not arp_result:  # 如果ARP表为空
            logger.error("Failed to obtain ARP table.")  # 记录错误日志
            return None  # 返回None
        logger.debug(arp_result)  # 记录调试日志
        lines = arp_result.split("\n")  # 按行分割ARP表
        for line in lines:
            line = line.strip()  # 去除行首尾的空格
            if self.host + " " in line and "---" not in line:  # 查找包含主机地址的行
                fields = re.split(r'\s+', line)  # 按空格分割行
                if len(fields) < 3:  # 如果字段数小于3
                    logger.error(f"Invalid ARP table entry: {line}")  # 记录错误日志
                    return None  # 返回None
                # 查找包含"-"的字段作为MAC地址
                mac_address = next((item for item in fields if "-" in item), None)
                break
        else:
            # 如果未找到匹配的行
            logger.error(f"Failed to obtain MAC address from ARP table for host {self.host}")
            return None  # 返回None
        if not mac_address:  # 如果MAC地址为空
            logger.error("Failed to obtain MAC address.")  # 记录错误日志
            return None  # 返回None
        # 格式化MAC地址为大写并去除"-"
        mac_address = mac_address.upper().replace("-", "")
        logger.info(f"MAC Address obtained successfully: {mac_address}")  # 记录日志
        return mac_address  # 返回MAC地址

    def enable_telnet(self):
        # 启用Telnet
        # 构造启用Telnet的URL
        url = f"http://{self.host}/cgi-bin/telnetenable.cgi?telnetenable=1&key=3CFC5C3191C0"
        logger.debug(f"Telnet Enable URL: {url}")  # 记录调试日志
        try:
            # 发送HTTP GET请求
            response = requests.get(url, timeout=5)
        except (requests.exceptions.Timeout, requests.exceptions.RequestException):
            # 捕获请求异常并记录日志
            logger.error("Failed to enable Telnet.")
            return False  # 返回False
        # 检查响应内容是否包含启用成功的标志
        if "if (1 == 1)" in response.text or "telnet开启" in response.text:
            logger.info("Telnet has been successfully enabled.")  # 记录日志
            self.method = 0 if "if (1 == 1)" in response.text else 1  # 设置启用方法
            return True  # 返回True
        else:
            logger.error("Failed to enable Telnet.")  # 记录错误日志
            return False  # 返回False

    def get_admin_password(self):
        # 获取管理员用户名和密码
        admin_password = None  # 初始化管理员密码
        admin_username = None  # 初始化管理员用户名
        if self.method == 0:  # 如果启用方法为0
            username = "root"  # 设置用户名为root
            password = f"Fh@{self.mac_address[-6:]}"  # 根据MAC地址生成密码
            logger.debug(f"Using Username: {username}")  # 记录调试日志
            logger.debug(f"Using Password: {password}")  # 记录调试日志
            try:
                # 使用Telnet连接到主机
                with telnetlib.Telnet(self.host, self.port) as tn:
                    tn.read_until(b"login: ")  # 等待登录提示
                    tn.write(username.encode('ascii') + b"\n")  # 输入用户名
                    tn.read_until(b"Password: ")  # 等待密码提示
                    tn.write(password.encode('ascii') + b"\n")  # 输入密码
                    tn.write(b"cat /flash/cfg/agentconf/factory.conf\n")  # 读取配置文件
                    tn.write(b"exit\n")  # 退出Telnet
                    result = tn.read_all().decode('ascii')  # 读取所有输出
            except Exception as e:
                # 捕获异常并记录日志
                logger.error(f"Telnet connection failed: {e}")
                return None  # 返回None
            try:
                # 使用正则表达式提取用户名和密码
                admin_username = re.search(r'TelecomAccount=(.*)', result).group(1).strip()
                admin_password = re.search(r'TelecomPasswd=(.*)', result).group(1).strip()
            except AttributeError as e:
                # 捕获解析异常并记录日志
                logger.error(f"Failed to parse factory.conf: {e}")
                return None  # 返回None
            logger.debug(f"factory.conf: {result}")  # 记录调试日志
        elif self.method == 1:  # 如果启用方法为1
            username = "admin"  # 设置用户名为admin
            password = f"Fh@{self.mac_address[-6:]}"  # 根据MAC地址生成密码
            logger.debug(f"Using Username: {username}")  # 记录调试日志
            logger.debug(f"Using Password: {password}")  # 记录调试日志
            try:
                # 使用Telnet连接到主机
                with telnetlib.Telnet(self.host, self.port) as tn:
                    tn.read_until(b"login:")  # 等待登录提示
                    tn.write(username.encode('utf-8') + b"\n")  # 输入用户名
                    tn.read_until(b"Password:")  # 等待密码提示
                    tn.write(password.encode('utf-8') + b"\n")  # 输入密码
                    time.sleep(0.5)  # 延时操作
                    tn.write(b"load_cli factory\n")  # 加载工厂模式
                    time.sleep(0.5)  # 延时操作
                    tn.write(b"show admin_pwd\n")  # 显示管理员密码
                    time.sleep(0.5)  # 延时操作
                    tn.write(b"show admin_name\n")  # 显示管理员用户名
                    time.sleep(0.5)  # 延时操作
                    tn.write(b"exit\n")  # 退出Telnet
                    time.sleep(0.5)  # 延时操作
                    tn.write(b"cfg_cmd get InternetGatewayDevice.DeviceInfo.X_CMCC_TeleComAccount.Username\n")  # 获取用户名
                    time.sleep(0.5)  # 延时操作
                    tn.write(b"cfg_cmd get InternetGatewayDevice.DeviceInfo.X_CMCC_TeleComAccount.Password\n")  # 获取密码
                    time.sleep(0.5)  # 延时操作
                    tn.write(b"exit\n")  # 退出Telnet
                    result = tn.read_all().decode('utf-8')  # 读取所有输出
            except Exception as e:
                # 捕获异常并记录日志
                logger.error(f"Telnet connection failed: {e}")
                return None  # 返回None
            try:
                # 使用正则表达式提取用户名和密码
                admin_username = re.search(r'admin_name=(.*)', result).group(1).strip()
                admin_password = re.search(r'admin_pwd=(.*)', result).group(1).strip()
            except AttributeError as e:
                # 捕获解析异常并记录日志
                logger.error(f"Failed to obtain Admin Username and Password form factory mode: {e}")
                if "Unknown command" in result:  # 如果输出包含未知命令
                    logger.debug("Entering experimental mode. This mode is based on tutorial methods and has not been fully tested. If you successfully retrieve the results, please provide feedback to the author via an issue report.")
                    obtain_result = obtain_value_from_text(result)  # 使用实验模式提取结果
                    if isinstance(obtain_result, list) and len(obtain_result) == 2:  # 如果提取结果为列表且长度为2
                        admin_username = obtain_result[0]  # 设置管理员用户名
                        admin_password = obtain_result[1]  # 设置管理员密码
                    else:
                        logger.error("Experimental mode failed.")  # 记录错误日志
                        return None  # 返回None
                else:
                    return None  # 返回None
            logger.debug(f"Telenet Result: {result}")  # 记录调试日志
        return admin_username, admin_password  # 返回管理员用户名和密码

    def manage_modem(self):
        # 管理Modem
        if self.enable_telnet():  # 如果成功启用Telnet
            return self.get_admin_password()  # 获取管理员用户名和密码
        else:
            return False  # 返回False

    def main(self):
        # 主函数
        self.host = self.set_host()  # 设置主机地址
        self.mac_address = self.get_mac_address()  # 获取MAC地址
        data = self.manage_modem()  # 管理Modem
        if isinstance(data, tuple) and data:  # 如果成功获取管理员用户名和密码
            clear_console()  # 清空控制台
            logger.info(f"Sucessfully obtained Admin Username and Password for {self.host}!")  # 记录日志
            logger.info(f"Username: {data[0]}")  # 输出用户名
            logger.info(f"Password: {data[1]}")  # 输出密码
        else:
            logger.error("Failed to obtain Admin Username and Password.")  # 记录错误日志
            logger.info(
                "Please follow the manual confirmation steps at "
                "`https://www.bilibili.com/read/cv21044770/` and modify the code if necessary.")  # 提示手动确认步骤
            exit(0)  # 退出程序


if __name__ == "__main__":
    manager = ModemManager()  # 创建Modem管理器实例
    manager.main()  # 调用主函数
