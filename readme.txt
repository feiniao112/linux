# LinuxCheck

LinuxCheck 是一个自动化的 Linux 系统安全检查工具，用于批量检查多台 Linux 服务器的安全状况。
可适应于Centos和Ubunt系统

## 功能特点

- 自动化批量检查多台服务器
- 全面的安全检查项目
- 自动收集和整理检查结果
- 最小化目标服务器影响，执行完成后自动清理

## 系统要求

- Linux 操作系统（本地执行机和目标服务器）
- expect 工具包
- SSH 服务可用

## 快速开始

### 1. 准备工作

克隆仓库到本地：

```bash
git clone https://github.com/feiniao112/LinuxCheck.git
cd LinuxCheck
```

### 2. 配置目标服务器

编辑 `hosts.txt` 文件，按以下格式添加服务器信息：

```
IP地址:普通用户名:普通用户密码:root密码
```

示例：
```
192.168.1.81:user:password123:rootpass
192.168.1.82:admin:password456:rootpass
```

### 3. 执行检查

```bash
sh login.sh
```
同时也支持针对单台进行检查，只需要将linuxcheck.sh这个文件上传就可以进行检查


### 4. 检查结果

执行完成后，结果文件会自动收集到本地执行机器上。

## 检查项目

本工具包含以下主要检查项目：

- 系统基本信息检查
- 用户账号安全检查
- 系统服务配置检查
- 网络配置安全检查
- 系统日志检查
- 文件系统安全检查

## 文件说明

- `linuxcheck.sh`: 主要的安全检查脚本
- `login.sh`: 批量登录和执行脚本
- `del.exp`: 清理脚本
- `get.exp`: 获取结果脚本
- `put.exp`: 上传脚本
- `sh.exp`: 执行脚本
- `hosts.txt`: 服务器配置文件

## 注意事项

1. 请确保本地执行机已安装 expect 工具包
2. 确保目标服务器的 SSH 服务正常运行
3. 建议使用普通用户执行，需要时会自动提升权限
4. 所有密码信息请妥善保管，避免泄露

## 贡献指南

欢迎提交 Issue 和 Pull Request 来帮助改进这个项目。

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 作者

- [@feiniao112](https://github.com/feiniao112)

## 更新日志

### v1.0.0
- 初始版本发布
- 支持基本的安全检查功能
- 支持批量服务器检查 
