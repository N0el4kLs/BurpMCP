# Burp Suite MCP Server

## 项目简介

BurpsuiteMCP 是一个模型上下文协议服务器，允许LLMs从Burp Suite代理历史记录中检索数据, 从而帮助研究人员和渗透测试人员更有效地进行安全测试和分析。 

该项目灵感来自于[GhidraMCP](https://github.com/LaurieWired/GhidraMCP)

## 主要功能

- **基于SQL的数据查询**：使用类似SQL的语法从Burp Suite代理历史记录中检索数据

目前支持从Burp Suite代理历史记录中检索数据包括:

- 原始请求
- 请求类型(POST, GET, etc.)
- 请求URL
- Host
- 请求体
- 原始响应
- 响应类型
- 响应状态码
- 响应体



相比于[官方的MCP](https://github.com/PortSwigger/mcp-server)：

优点：

1. 可以指定 `HTTP History` 的返回字段, 避免同意返回带来上下文过长的问题。

缺点：

1. 其他功能没官方多
2. 也没有UI

## 演示

<video src="README.assets/out.mp4"></video>


## 安装说明

### 前提条件

- Java 17 或更高版本
- Python 3.11或更高版本

### 安装步骤

1. **安装Burp Suite扩展**：
   - 下载最新的`MCPBurpExtension.jar`文件
   - 在Burp Suite中，打开"扩展"选项卡
   - 点击"添加"按钮，选择"Java扩展"
   - 选择下载的JAR文件
   - 扩展将在端口**8889**上启动HTTP服务器

2. **安装Python依赖**：
   
   ```bash
   uv sync
   ```

## 使用指南

### 基本用法


use MCP Client 

```json
{
  "mcpServers": {
    "burpsuite": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/burpsuite_mcp.py"
      ]
    }
  }
}
```



