1. 核心特征文件 - Agent配置

  • 文件路径: Extenders/beacon_agent/config.json
  • 关键特征:
    • "agent_watermark": "be4c0149" - 这是Beacon Agent的水印标识
    • "agent_name": "beacon" - Agent类型标识
    • 支持的监听器类型: ["BeaconHTTP", "BeaconTCP", "BeaconSMB"]

  2. 通信配置文件

  • 文件路径: Extenders/beacon_agent/src_beacon/beacon/config.cpp
  • 关键特征:
    • 包含加密的通信配置文件（HTTP/SMB/TCP三种类型）
    • 每种监听器类型都有特定的加密配置数据
    • 配置数据大小固定（HTTP:190字节，SMB:56字节，TCP:41字节）

  3. Gopher Agent特征

  • 文件路径: Extenders/gopher_agent/config.json
  • 关键特征:
    • "agent_watermark": "904e5493" - Gopher Agent的水印标识
    • "agent_name": "gopher" - 不同的Agent类型

  4. Shellcode存根文件

  • 文件路径: Extenders/beacon_agent/src_beacon/files/stub.x64.bin 和 stub.x86.bin
  • 关键特征:
    • 大小都是1023字节
    • 用于生成不同架构的shellcode

  5. API哈希特征

  • 文件路径: Extenders/beacon_agent/src_beacon/files/hashes.py
  • 关键特征:
    • 包含DJBA2哈希算法实现
    • 预定义了大量Windows API函数的哈希值
    • 用于动态API解析，避免导入表暴露

  6. 服务器端特征

  • 文件路径: AdaptixServer/profile.json
  • 关键特征:
    • 默认监听端口: 4321
    • 服务器标识: "Adaptix Version": "v0.10"
    • 404页面伪装: 404page.html

  主要的检测特征总结：

  1. 水印标识:
    • Beacon Agent: be4c0149
    • Gopher Agent: 904e5493
  2. 通信配置: 固定大小的加密配置文件
  3. API哈希: 使用DJBA2算法的大量API哈希值
  4. 架构支持: x86/x64的shellcode存根
  5. 监听器类型: HTTP/SMB/TCP/Gopher四种主要类型