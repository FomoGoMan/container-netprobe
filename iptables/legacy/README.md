### 环境
1. `系统 centos7  Linux 3.10.0-1160.105.1.el7.x86_64`
2. `iptables v1.4.21`


### 说明
本程序使用uid的方式监控容器流量，请在启动容器的时候指定没有别人共用uid，否则统计程序会统计uid下的所有进程的流量，这显然会导致结果失真（偏大）
```
# 示例：启动一个以 UID=1000、GID=1000 运行的容器
docker run -d --name mycontainer \
  --user 1000:1000 \
  --network host \
  your_image
```

### Demo测试
1. 启动测试容器
```
docker run --network host --user 1234:1234 -d amouat/network-utils tail -f /dev/null
```

2. 编译监控程序并启动
```
cd cmd/
go build main.go
./main <container id> #填入上面启动的容器的ID
```

3. 进入测试容器产生上行流量并查看监控程序输出
```
docker exec -it <container id> bash

# 使用循环持续发送请求（按 Ctrl+C 停止）
while true; do curl -s http://httpbin.org/get >/dev/null; sleep 1; done
```

---

### 故障排查：确认内核模块支持情况

> 查看 grep `CONFIG_NETFILTER_XT_MATCH_OWNER /boot/config-$(uname -r)`
`CONFIG_NETFILTER_XT_MATCH_OWNER=m`说明内核模块已经以模块形式存在，但可能未加载

---

### **1. 加载 `xt_owner` 内核模块**
```bash
# 加载模块
sudo modprobe xt_owner

# 验证模块是否加载
lsmod | grep xt_owner
```
• 输出应包含 `xt_owner`，例如：
  ```
  xt_owner                16384  0
  ```

---

### **2. 验证 `iptables` 是否支持 `--pid-owner`**
```bash
iptables -m owner --help | grep pid-owner
```
• 如果输出包含 `--pid-owner`，表示功能已启用。

---

### **3. 测试 `--pid-owner` 规则**
```bash
# 添加测试规则（假设要监控 PID 为 1234 的进程）
sudo iptables -A OUTPUT -m owner --pid-owner 1234 -j ACCEPT

# 查看规则是否生效
sudo iptables -L -v -n
```
• 如果规则存在且无报错，说明功能正常。

---

### **4. 设置模块开机自动加载（可选）**
为了避免重启后模块失效，需将模块添加到启动加载列表：
```bash
echo "xt_owner" | sudo tee /etc/modules-load.d/xt_owner.conf
```
---
