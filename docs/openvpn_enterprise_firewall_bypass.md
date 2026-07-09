# Mihomo OpenVPN 企业级连通性攻坚：技术复盘与深度剖析

本记录详细复盘了我们在适配极其严格的企业级 OpenVPN 架构（如深信服 / 定制网关 / 强 IPS 系统）时，遇到的重重技术阻碍，以及我们一步步抽丝剥茧、最终实现协议级原生潜入的全过程。

---

## 战役 1：遭遇 UDP 分片黑洞（MTU 与 PUSH_REPLY）

### 现象与发现
在最初的测试中，客户端能够成功完成 TLS 握手，但一直卡在等待服务端下发网络配置（`PUSH_REPLY`）的阶段，随后因超时不断断线重连。
通过抓包和日志分析，我们发现服务端需要下发的路由表（如 `172.16.232.0/22` 等内网网段）、DNS 配置以及拓扑参数非常长。这些参数组合在一起形成了一个超大的 UDP 控制报文。
当这个超大报文通过公网或者家用 NAT 路由器时，由于超出了标准 MTU（最大传输单元），触发了 IP 分片。而某些严苛的网络环境（或运营商策略）会直接丢弃 UDP 分片包，导致客户端永远收不到最终的网络配置。

### 核心改动
为了强制服务端缩小每次发送的报文体积，我们在 `transport/openvpn/keymethod.go` 中引入了原版 `mihomo` 缺失的动态 `MTU` 下发机制：
1. 解析 YAML 配置文件中的 `mtu` 参数（如 `1360`）。
2. 在向服务端发送的 `client options string` 中，精准拼接 `link-mtu` 和 `tun-mtu`。
3. 服务端收到较小的 MTU 协商后，主动将超长的 `PUSH_REPLY` 拆分成多个安全的小体积 UDP 包，成功穿透了网络黑洞。

---

## 战役 2：防暴力破解封锁与 MAC 地址放行

### 现象与发现
第二天继续测试时，发现一启动连接，立刻遭遇服务端秒踢，并返回 `AUTH_FAILED` 控制报文。
起初我们怀疑是协议实现问题，但通过代码回溯发现 `go-openvpn` 是在客户端优雅退出时发送 `OCCExit` 包的，不存在所谓的“幽灵会话”。
真正的根因是：昨天因为 MTU 丢包导致的 24 小时内疯狂断线重连（数千次请求），触发了企业网关的**IPS 防暴破阻断策略**，导致原物理机的 MAC 地址 (`68:79:09:4c:ed:c6`) 被硬核封禁。

### 核心改动
我们利用 `ics-openvpn` 手机端能够成功连接的线索，确认了 VPN 服务端启用了**设备 MAC 地址准入白名单**。
我们在 `mihomo` 的 YAML 配置文件中，利用 `peer-info` 机制注入了未被封禁且合法的手机 MAC 地址：
```yaml
IV_HWADDR: "65:33:36:64:38:30:37"
```
成功越过了第一道设备封锁线。

---

## 战役 3：硬核 DPI 指纹检测（“伪装者”行动）

### 现象与发现
在使用合法的 MAC 地址后，服务端依然顽固地返回 `AUTH_FAILED`。
通过对比成功连接的 `ics-openvpn` 与 `mihomo` 在控制通道（Control Channel）中发送的 `peer-info`（客户端特征信息），我们发现：
旧版的 `mihomo` 发送的是非常扎眼的第三方标识：`IV_VER=mihomo-openvpn` 以及极新的协议版本 `IV_PROTO=6`。
极其严格的企业防火墙显然配置了**客户端特征指纹库**，对于非官方标准的握手报文一律判定为恶意破解工具或违规接入。

### 核心改动
我们在 `keymethod.go` 中对客户端指纹进行了彻底的“整容”，加入了老旧且标准的 OpenVPN 协议标志：
- `IV_PROTO=2` (替代 6)
- `IV_NCP=2` (启用密码协商)
- `IV_TCPNL=1`, `IV_LZO=1`, `IV_COMP_STUBv2=1` 等各种官方客户端必带的底层环境光环。
- 伪装平台为 `mac` 并带有 `IV_GUI_VER=net.tunnelblick.tunnelblick...` 等强伪装属性。

---

## 战役 4：与“顺序强迫症”防火墙的终极博弈

### 现象与发现
本以为大功告成，当我们试图优雅地将上述伪装参数剥离底层源码、转移到用户的 YAML 配置文件中让其自行控制时，连接再次失败，秒回 `AUTH_FAILED`。

经过逐帧比对报文，我们揪出了一个令人毛骨悚然的细节：
Go 语言在解析 YAML 配置的 map 结构时，会**自动按字母顺序 (A-Z) 对键名进行重新排序** (`sort.Strings(keys)`)。
原本在代码中硬编码的正确顺序是：`IV_VER` -> `IV_PLAT` -> `IV_PROTO` -> `IV_NCP` ...
排序后变成了：`IV_COMP_STUB` -> `IV_GUI_VER` -> `IV_HWADDR` -> `IV_LZO` -> `IV_NCP` -> `IV_PLAT` -> `IV_PROTO` -> `IV_VER`...

企业网关的 DPI 深层报文检测不仅校验内容，更使用了**严格的正则表达式前缀匹配**（例如强制要求报文必须以 `IV_VER=` 开头，紧跟 `IV_PLAT=` 等）。一旦顺序打乱，防火墙直接判定为非标准客户端篡改行为。

### 官方源码级别铁证
官方客户端（如 `ics-openvpn` 使用的 C/C++ 核心）之所以没有排序困扰，是因为他们在底层使用原始的 `buf_printf` 按顺序硬编码组装。
参考 [OpenVPN 官方源码 ssl.c (Line 1912)](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/ssl.c#L1912)：

```c
static bool push_peer_info(struct buffer *buf, struct tls_session *session) {
    // ...
    if (session->opt->push_peer_info_detail > 1) {
        /* push version */
        buf_printf(&out, "IV_VER=%s\n", PACKAGE_VERSION);          // 必须位于第 1 位
        
        /* push platform */
#if defined(TARGET_DARWIN)
        buf_printf(&out, "IV_PLAT=mac\n");                         // 紧跟第 2 位
#endif
        /* TCP non-linear */
        buf_printf(&out, "IV_TCPNL=1\n");                          // 第 3 位
    }

    if (session->opt->push_peer_info_detail > 0) {
        // ...
        if (tls_item_in_cipher_list("AES-128-GCM", session->opt->config_ncp_ciphers)) {
            buf_printf(&out, "IV_NCP=2\n");                        // 第 4 位
        }
        buf_printf(&out, "IV_CIPHERS=%s\n", session->opt->config_ncp_ciphers); // 第 5 位
        buf_printf(&out, "IV_PROTO=%d\n", iv_proto);               // 第 6 位
    }
    // ...
}
```
> 可以看出，官方发出的 `peer-info` 报文头部顺序是**天生写死、雷打不动的！**，根本没有经过任何哈希字典或排序逻辑。

### 最终形态修复
为了满足网关的序列检测要求，我们在 `transport/openvpn/keymethod.go` 中，将最核心的 8 个官方协议变量（`IV_VER`, `IV_PLAT`, `IV_PROTO`, `IV_NCP`, `IV_TCPNL`, `IV_LZO`, `IV_COMP_STUBv2`, `IV_COMP_STUB`）**硬编码固定顺序写入报文头部**。
并在后续追加用户配置文件中其它参数时，主动过滤掉这 8 个已固化的字段以防止重复。

至此，`mihomo` 发出的握手包成为了一个不仅特征完美，而且结构排序无懈可击的原生镜像。隧道成功建立，数据通道完全打通，内网路由下发一切正常。

---
**本次维护不仅使得 Mihomo 完美接入了超严苛的企业级内网，更为后续适配复杂的商业 VPN 网关留下了极具价值的 DPI 逆向分析经验。**
