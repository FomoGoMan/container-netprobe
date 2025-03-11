本代码使用 `iptables` 的 `cgroup --path` 特性，需要满足以下最低版本的 `iptables` 和 Linux 内核：

---

### **1. iptables 版本**
`cgroup --path` 是 `iptables` 的一个扩展功能，需要 `iptables` 版本 **1.8.0** 或更高版本。

• **检查 `iptables` 版本**：
  ```bash
  iptables --version
  ```
  输出示例：
  ```
  iptables v1.8.7 (legacy)
  iptables v1.8.7 (nf_tables) 等等
  ```
  如果版本低于 `1.8.0`，需要升级 `iptables`。

• **升级 `iptables`**：
  • 对于 Ubuntu/Debian：
    ```bash
    sudo apt-get update
    sudo apt-get install iptables
    ```
  • 对于 CentOS/RHEL：
    ```bash
    sudo yum install iptables
    ```

---

### **2. Linux 内核版本**
`cgroup --path` 依赖于 Linux 内核的 `cgroup` 功能，需要 Linux 内核版本 **4.8** 或更高版本。

• **检查 Linux 内核版本**：
  ```bash
  uname -r
  ```
  输出示例：
  ```
  5.4.0-42-generic
  ```
  如果内核版本低于 `4.8`，需要升级内核。

• **升级 Linux 内核**：
  • 对于 Ubuntu/Debian：
    ```bash
    sudo apt-get update
    sudo apt-get install linux-image-<version>
    ```
  • 对于 CentOS/RHEL：
    ```bash
    sudo yum install kernel
    ```

---

### **3. 验证 `cgroup --path` 支持**
在满足上述版本要求后，可以通过以下命令验证 `cgroup --path` 是否可用：

```bash
iptables -m cgroup --help
```

输出示例：
```
cgroup match options:
[!] --path cgroup_path Match cgroup path
```

如果输出中包含 `--path cgroup_path`，说明 `cgroup --path` 功能已启用。

---

### **4. 其他依赖**
除了 `iptables` 和内核版本外，还需要确保以下依赖已安装：

• **cgroup 工具**：
  • 确保 `cgroup` 工具已安装，用于创建和管理 cgroup。
  • 对于 Ubuntu/Debian：
    ```bash
    sudo apt-get install cgroup-tools
    ```
  • 对于 CentOS/RHEL：
    ```bash
    sudo yum install libcgroup-tools
    ```

• **cgroup v2**：
  • `cgroup --path` 功能依赖于 `cgroup v2`，确保系统已启用 `cgroup v2`。
  • 检查是否启用了 `cgroup v2`：
    ```bash
    cat /proc/filesystems | grep cgroup2
    ```
    如果输出中包含 `cgroup2`，说明 `cgroup v2` 已启用。

---

### **结论**
• **iptables 版本**：需要 `1.8.0` 或更高版本。

• **Linux 内核版本**：需要 `4.8` 或更高版本。

• **cgroup 工具**：确保已安装 `cgroup-tools` 或 `libcgroup-tools`。

• **cgroup v2**：确保系统已启用 `cgroup v2`。
