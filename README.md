# subconverter-worker

[subconverter](https://github.com/tindy2013/subconverter) 的 Cloudflare Workers 移植版 —— 将各类代理订阅在多种客户端配置格式之间转换。基于上游 `asdlokj1qpi23/subconverter` fork，使用 **TypeScript 全量重写**（非 WASM），原生运行在 workerd 上。

## 功能

- **输入**：`ss://` `ssr://` `vmess://` `vless://` `trojan://` `hysteria://` `hysteria2://` `hy2://` `tuic://` `anytls://` `mieru(s)://` `socks://` `http(s)://` `Netch://` `ssd://`、Clash YAML、Surge INI、sing-box JSON、V2Ray/SS/SSR/SSTap/Netch 配置文件、base64 订阅
- **输出目标**：`clash` `clashr` `surge&ver=2/3/4/5` `surfboard` `quan` `quanx` `loon` `mellow` `ss` `ssr` `sssub` `ssd` `v2ray` `trojan` `vless` `hysteria2` `mixed` `singbox`
- **端点**：`/sub` `/getruleset` `/getprofile` `/surge2clash` `/render` `/version` `/updateconf` `/readconf` `/refreshrules` `/flushcache` `/get` `/getlocal`，以及 `[[aliases]]` 短链接（`/clash` `/surge` 等）
- `/sub` 全部 30+ 查询参数、外部配置（INI/TOML/YAML，含 `config/ACL4SSR*.ini` 全套预设）、`Subscription-UserInfo` 流量信息、Emoji/改名/过滤/排序、Gist 上传、UA 自动识别（`target=auto`）
- 内嵌上游 `base/` 全部资产（模板、外部配置预设、规则列表），开箱即用

## 部署

```bash
npm install
npx wrangler login
npx wrangler deploy
```

免费版即可运行（打包体积 gzip ≈ 750KB，限额 3MB）。

> **CPU 提示**：免费版单请求 CPU 限额 10ms。小型订阅 + `expand=false`（provider 模式）没问题；大订阅 + 全量规则展开可能超限，建议 Workers Paid（30s CPU）。

### 环境变量（wrangler.jsonc [vars]）

| 变量 | 说明 |
|---|---|
| `API_MODE` | `true` 时禁用 `/get` `/getlocal` 与本地订阅文件（默认 true） |
| `API_TOKEN` | 覆盖 pref 中的 `api_access_token` |
| `MANAGED_PREFIX` | 覆盖 `managed_config_prefix`（Surge `#!MANAGED-CONFIG` 前缀） |
| `MAX_NODES` / `MAX_RULESET_LINES` | 单请求节点/规则行数熔断（0 = 不限） |

### KV（可选）

绑定名为 `KV` 的 KV 命名空间即可持久化 `/updateconf` 写入的 pref 与 `gistconf.ini`；未绑定时仅 isolate 内存态。

```jsonc
// wrangler.jsonc
"kv_namespaces": [{ "binding": "KV", "id": "<your-kv-id>" }]
```

## 开发与测试

```bash
npm run dev        # wrangler dev (http://127.0.0.1:8787)
npm test           # vitest（@cloudflare/vitest-pool-workers，跑在 workerd 里）
npm run sync-base  # 从 ../subconverter/base/ 重新同步内嵌资产
npx tsc --noEmit   # 类型检查
```

快速验证：

```bash
curl "http://127.0.0.1:8787/version"
# 订阅内容需为 base64(链接列表)（标准订阅格式）
SUB=$(printf 'ss://%s#HK' "$(printf 'aes-256-gcm:pass@1.2.3.4:8388' | base64 -w0)" | base64 -w0)
curl "http://127.0.0.1:8787/sub?target=mixed&url=data:text/plain;base64,$SUB"
```

## 与上游的差异

移植保持逐函数对照（解析器/导出器/编排层语义、参数默认值、缓存 TTL 与上游一致），以下为运行时差异：

| 项 | 上游 | 本项目 |
|---|---|---|
| QuickJS 脚本（`script:` 链接 / `filter_script` / 排序脚本 / `!!GROUP=script:`） | QuickJS 执行 | 跳过（记 warning） |
| cron 定时任务 | libcron + QuickJS | 无（Workers Cron 可自行扩展） |
| `proxy=` socks5/http 代理抓取订阅 | libcurl 支持 | 不支持裸 socket；仅 `cors:` 前缀可用 |
| TLS 证书校验 | curl 默认关闭校验 | Workers fetch 无法关闭，自签名订阅源会失败 |
| 磁盘缓存 `cache/` | 文件系统 | isolate 内存缓存（TTL 语义一致：60s/300s/21600s） |
| `fileWrite`（/updateconf、gistconf.ini） | 本地文件 | isolate 内存 + 可选 KV |
| `resolve_hostname`（Surge SSR external） | getaddrinfo | 不可用（无 DNS 解析 API） |
| YAML 输出风格 | yaml-cpp | `yaml` 库，块/流风格与键序可能有 cosmetic 差异（语义等价） |
| 并发 | 4 线程池 | 单 isolate 顺序处理；规则集抓取并行 `Promise.all` |
| 磁盘缓存的 `/flushcache` | 删除 cache/ 目录 | 清空内存缓存 |

已知保留的上游行为（bug-compatible）：单行订阅（无换行）按空格切分导致 remark 含空格被截断；`target=vless/hysteria2` 在 `proxyToSingle` 中的位图互换；`split` 对结尾分隔符不产生空尾元素等。

## 目录结构

```
src/
├── index.ts            # Worker 入口：路由表、CORS、鉴权、循环检测、别名
├── routes/             # 各端点 handler（/sub /getruleset /getprofile /surge2clash /render /admin）
├── core/
│   ├── parser/         # 协议解析（对照 subparser.cpp，每协议一文件 + clash/surge/singbox 容器）
│   ├── export/         # 格式导出（对照 subexport.cpp：clash/surge/single/quan/quanx/loon/mellow/singbox/ssd）
│   ├── orchestrator.ts # /sub 主流程（对照 interfaces.cpp subconverter()）
│   ├── nodemanip.ts    # 节点获取/过滤/改名/emoji/排序（对照 nodemanip.cpp）
│   ├── ruleconvert.ts  # 规则集转换（对照 ruleconvert.cpp + renderClashScript）
│   ├── settings.ts     # pref 加载（TOML/YAML/INI）+ 外部配置 + refreshRulesets
│   ├── info.ts         # Subscription-UserInfo（对照 infoparser.cpp）
│   ├── template.ts     # inja 兼容模板渲染（对照 templates.cpp）
│   └── proxy.ts        # Proxy 数据模型（~85 字段，对照 proxy.h）
├── lib/                # 基础库：PCRE→JS 正则适配器、base64/md5/INI/tribool/fetch+缓存/VFS/模板引擎
└── embed/              # 内嵌上游 base/ 资产（scripts/sync-base.ts 生成）
```

## License

遵循上游 subconverter 的 GPL-3.0 许可证。
