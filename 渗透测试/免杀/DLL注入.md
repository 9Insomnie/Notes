## 一、DLL注入技术基础

### 1.1 核心概念
DLL注入是将动态链接库（DLL）强制加载到目标进程地址空间的技术，使注入的代码在目标进程上下文中执行，从而：
- 访问/修改进程内存数据
- 拦截API调用（Hook）
- 扩展或修改程序功能
- 实现进程隐藏与 persistence

**技术价值**：逆向工程、安全测试、合法的游戏Mod开发、调试器扩展。

---

## 二、Windows底层原理（关键）

### 2.1 `LdrLoadDll` 工作机制
根据Windows内核研究，DLL加载分为两个核心阶段：
1. **映射阶段**：`LdrpFindOrPrepareLoadingModule` 通过 `NtMapViewOfSection` 将DLL文件映射到内存
2. **初始化阶段**：`LdrpPrepareModuleForExecution` 按依赖关系逆序调用 `DllMain` 入口点

**早期级联注入**正是利用了这一机制：通过篡改进程初始化时的 `g_pfnSE_DllLoaded` 指针和 `g_ShimsEnabled` 标志，在Windows加载器执行早期注入恶意代码。

---

## 三、主流注入方法详解

### 3.1 **经典方法：CreateRemoteThread + LoadLibrary**

**原理**：在目标进程创建远程线程执行 `LoadLibraryA` 加载指定DLL。

**实现步骤**：
```cpp
// 核心API调用链
OpenProcess()              // 1. 获取目标进程句柄
VirtualAllocEx()           // 2. 在目标进程分配内存
WriteProcessMemory()       // 3. 写入DLL路径字符串
GetProcAddress()           // 4. 获取LoadLibraryA地址
CreateRemoteThread()       // 5. 创建远程线程执行加载
```

**完整示例代码**（教学简化版）：
```cpp
#include <windows.h>
#include <iostream>

bool InjectDLL(DWORD pid, const char* dllPath) {
    // 1. 打开目标进程
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE, pid
    );
    if (!hProcess) return false;

    // 2. 分配内存
    size_t pathLen = strlen(dllPath) + 1;
    LPVOID pRemoteMem = VirtualAllocEx(
        hProcess, NULL, pathLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return false;
    }

    // 3. 写入DLL路径
    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath, pathLen, NULL)) {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 4. 获取LoadLibraryA地址（kernel32在大多数进程基址相同）
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = 
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    // 5. 创建远程线程
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0, pLoadLibrary, pRemoteMem, 0, NULL
    );
    if (!hThread) {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 等待加载完成
    WaitForSingleObject(hThread, INFINITE);
    
    // 清理资源
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return true;
}
```

---

### 3.2 **SetWindowsHookEx 钩子注入**

**原理**：利用Windows消息钩子机制，将DLL加载到拥有目标线程窗口的进程中。

**关键代码**（Delphi示例）：
```delphi
// 在DLL中定义钩子函数
function GetMsgProc(nCode: Integer; wParam: WPARAM; lParam: LPARAM): LRESULT; stdcall;
begin
    if nCode = HC_ACTION then begin
        // 首次调用时创建注入界面
        if g_hInjectFrm = 0 then begin
            g_hInjectFrm := CreateInjectForm;
        end;
    end;
    Result := CallNextHookEx(g_hHook, nCode, wParam, lParam);
end;

// 设置钩子
function SetInjectHook(dwThreadId: DWORD): Boolean;
begin
    Result := False;
    if dwThreadId <> 0 then begin
        g_hHook := SetWindowsHookEx(WH_GETMESSAGE, @GetMsgProc, 
                                   g_hInstance, dwThreadId);
        Result := (g_hHook <> 0);
    end;
end;
```

---

### 3.3 **注册表注入（AppInit_DLLs）**

**原理**：利用 `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` 键值，系统启动时会自动加载指定的DLL。

**特点**：
- 系统级注入，影响所有GUI进程
- 需管理员权限
- 现代Windows系统已默认禁用（受安全策略限制）

---

### 3.4 **手动映射（Manual Map）高级技术**

**优势**：
- 不调用 `LoadLibrary`，绕过部分AV/EDR检测
- 无需在磁盘留下DLL文件
- 支持从内存直接加载

**核心步骤**：
1. 手动解析PE头，在目标进程分配内存
2. 复制PE节区，修复重定位表
3. 手动加载导入表（IAT）
4. 调用 `DllMain` 并执行TLS回调

**代码框架**：
```cpp
// 伪代码流程
void ManualMap(HANDLE hProcess, LPVOID pDllData) {
    // 1. 解析PE头
    PIMAGE_NT_HEADERS pNtHeaders = GetNtHeaders(pDllData);
    
    // 2. 分配内存并映射节区
    LPVOID pBase = VirtualAllocEx(...);
    WriteProcessMemory(...); // 复制各节
    
    // 3. 修复重定位
    FixRelocations(pBase, pNtHeaders);
    
    // 4. 解析导入表
    ResolveImports(hProcess, pBase, pNtHeaders);
    
    // 5. 执行DllMain
    CreateRemoteThread(pBase + pNtHeaders->AddressOfEntryPoint);
}
```

---

## 四、高级注入技术

### 4.1 **Early Cascade Injection（早期级联注入）**

最新研究显示的高级免杀技术：
1. 以挂起状态创建子进程
2. 在 `ntdll.dll` 中定位并篡改 `g_pfnSE_DllLoaded` 指针和 `g_ShimsEnabled` 标志
3. 恢复进程，使加载器执行恶意stub
4. stub禁用shim机制后，通过APC注入主payload

**特点**：在进程初始化早期阶段完成注入，绕过大部分用户态检测。

---

## 五、检测与防御技术

### 5.1 **检测方法**

**工具层**：
- **Process Explorer/Process Hacker**：查看进程模块列表，发现非微软签名DLL
- **VMMap**：分析进程内存，识别异常内存区域
- **WinDbg**： attach进程，检查线程调用栈

**技术特征**：
```plaintext
进程注入检测指标：
1. 异常线程创建（CreateRemoteThread）
2. 内存异常分配（PAGE_EXECUTE_READWRITE）
3. 可疑API调用序列（OpenProcess→VirtualAllocEx→WriteProcessMemory）
4. 非标准模块加载路径（临时目录、网络路径）
```

### 5.2 **防御机制**

| 防御层级 | 技术手段 |
|----------|----------|
| **应用层** | DLL签名验证、代码完整性检查（CI） |
| **系统层** | 启用HVCI（Hypervisor-Protected Code Integrity）、ASR（Attack Surface Reduction）规则 |
| **内核层** | 通过驱动监控 `PsSetCreateProcessNotifyRoutine` 和 `ObRegisterCallbacks` |
| **EDR** | 行为分析、内存扫描、API Hook检测 |

---

## 六、合法学习实践环境

### 6.1 **推荐实验环境**
- **虚拟机**：VMware/VirtualBox + Windows 10/11 x64
- **开发工具**：Visual Studio 2022、Windows SDK
- **调试工具**：x64dbg、WinDbg Preview
- **监控工具**：Process Monitor、API Monitor