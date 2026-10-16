# 在新 macOS 上构建本分支内核并替换 ClashX.Meta

适用分支：`feat-openvpn-upstream`（基于上游 `Alpha`，额外包含 OpenVPN 的 A–H 项改动）。

## 1. 克隆并切换分支

```bash
git clone git@github.com:Easy-Ez/mihomo.git
cd mihomo
git checkout feat-openvpn-upstream
```

可选：添加上游远程，便于以后同步 `Alpha`。

```bash
git remote add upstream git@github.com:MetaCubeX/mihomo.git
```

## 2. 构建

要求 Go 1.23 或更高。必须带 `with_gvisor` tag 和 `Version` / `BuildTime` 两个 ldflags，缺一不可：
ClashX.Meta 启动时会执行 `core -v`，要求第一行按空格切分正好 13 个 token，否则静默回退到内置内核，表现为"替换后不生效"。

整行复制执行（单行，不要手动换行）：

```bash
VERSION=alpha-g$(git rev-parse --short HEAD); BUILDTIME=$(LC_ALL=C date -u); CGO_ENABLED=0 GOARCH=arm64 go build -tags with_gvisor -trimpath -ldflags "-X 'github.com/metacubex/mihomo/constant.Version=${VERSION}' -X 'github.com/metacubex/mihomo/constant.BuildTime=${BUILDTIME}' -w -s -buildid=" -o mihomo . && ./mihomo -v | head -1 | awk '{print NF}'
```

- 最后必须输出 `13`。
- Intel 机器把 `GOARCH=arm64` 改成 `GOARCH=amd64`。
- `LC_ALL=C` 不能省，中文 locale 下 `date -u` 的 token 数不对。

## 3. 替换 ClashX.Meta 内核

不要替换 `~/Library/Application Support/com.metacubex.ClashX.meta/.private_core/` 子目录里的文件，
那个每次启动都会从 app 包内重新解压并做 hash 校验，替换会被覆盖。正确做法是走 alpha core：

1. ClashX 菜单点一次 **Update Alpha Meta Core**，让它在
   `~/Library/Application Support/com.metacubex.ClashX.meta/` **根目录**生成内核文件。
2. 勾选 **Use Alpha Core**（或 `defaults write com.metacubex.ClashX.meta useAlphaCore -bool true`）。
3. 完全退出 ClashX，执行：

```bash
CORE="$HOME/Library/Application Support/com.metacubex.ClashX.meta/com.metacubex.ClashX.ProxyConfigHelper.meta"
cp "$CORE" "$CORE.backup"
cp mihomo "$CORE" && chmod +x "$CORE" && codesign -s - --force "$CORE"
"$CORE" -v | head -1
```

4. 重新打开 ClashX。ClashX 设置页显示的内核版本应为 `alpha-g<commit>`。

以后再点 **Update Alpha Meta Core** 或 ClashX 自身升级都会把内核覆盖回官方版本，需要重做第 3 步。

## 4. 配置要点

直接复用现有机器的 ClashX 配置（`~/.config/clash.meta/<name>.yaml`）。OpenVPN 节点里以下几项缺一不可：

```yaml
    handshake-timeout: 30      # 服务端准入校验在握手中跑（约 7s），必须脱离 5s 拨号超时
    ping: 10
    ping-restart: 60           # 不写则被踢或切网后永远不自愈
    peer-info:
      # 服务端从非公司 IP 接入时按 OpenVPN 2.4 官方客户端指纹准入，内核会按官方顺序发送这些键
      IV_VER: "3.8.4"
      IV_PLAT: "mac"
      IV_PROTO: "2"
      IV_NCP: "2"
      IV_TCPNL: "1"
      IV_LZO: "1"
      IV_COMP_STUBv2: "1"
      IV_COMP_STUB: "1"
      IV_HWADDR: "<白名单内的 MAC>"   # 沿用现有配置里的值，不要改成新机器自己的 MAC
```

- 服务端同一账号只允许一个会话，两台机器不要同时连，否则互相踢。
- 首个触发握手的请求会失败一次（约 5s），后续请求复用隧道，属预期。

## 5. 排查

- ClashX 历史日志：`~/.config/clash.meta/logs/<启动时间>/clashx_core_*.log`（5MB 轮转）。
- 实时日志：`curl -sN http://127.0.0.1:9090/logs?level=debug`。
- 搜 `[OpenVPN]` 行：`handshake started` → `TLS established` → `server options` → `client peer-info` → `PUSH_REPLY` → `data channel ready` → `handshake complete`，卡在哪一步一目了然。
- `AUTH_FAILED` 的三种来源：MAC 不在白名单、peer-info 指纹不符（非公司 IP 时）、同账号被另一会话顶掉。先看 `client peer-info` 行。
- 失败握手不要反复刷，服务端有防暴破策略会封 MAC。
