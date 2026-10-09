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
| `API_TOKEN` | 覆盖 pref 中的 `api_access_token`；`/readconf`、`/updateconf` 之后会重新应用 |
| `MANAGED_PREFIX` | 覆盖 `managed_config_prefix`（Surge `#!MANAGED-CONFIG` 前缀） |
| `MAX_NODES` / `MAX_RULESET_LINES` | 单请求节点/规则行数熔断（0 = 不限） |

> 注意：`wrangler.jsonc` 里的 `[vars]` 优先级高于同名进程环境变量。本地临时覆盖用 `npx wrangler dev --var API_TOKEN:xxx`；线上用 `npx wrangler secret put API_TOKEN` 或改 `[vars]`。

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

测试覆盖（`npm test`，139 用例 / 11 文件）：

| 文件 | 覆盖 |
|---|---|
| `string` / `base64` / `regex` | C++ 语义基础库（split/atoi、宽松 base64、PCRE2→JS 适配器） |
| `parser` | 各协议链接、Clash/Surge/sing-box 容器、明文订阅的 bug-compatible 行为 |
| `template` | inja 子集渲染 |
| `config` / `export` | pref 规则解析、导出器基本输出 |
| `ruleset` | `/getruleset` 全部 type 1-6、`[]` 内联规则、`from_ini` 绑定语义 |
| `routes` | `/version` `/readconf` `/updateconf` `/flushcache` `/get` `/getlocal` `/render` `/getprofile` |
| `surge2clash` | Surge→Clash 完整转换（proxies / proxy-groups shim / rules） |
| `orchestrator` | `/sub` 全链路：各 target 结构断言、`Subscription-UserInfo`、`target=auto` UA 识别、YAML/JSON 可解析性 |

快速验证：

```bash
curl "http://127.0.0.1:8787/version"
# 订阅内容需为 base64(链接列表)（标准订阅格式）
SUB=$(printf 'ss://%s#HK' "$(printf 'aes-256-gcm:pass@1.2.3.4:8388' | base64 -w0)" | base64 -w0)
curl "http://127.0.0.1:8787/sub?target=mixed&url=data:text/plain;base64,$SUB"
```

> 本地带 token 验证受保护端点：
> `npx wrangler dev --var API_MODE:true --var API_TOKEN:secret-token`
> 然后 `curl "http://127.0.0.1:8787/getprofile?name=profiles/example_profile.ini&token=secret-token"`。

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

已知保留的上游行为（bug-compatible）：单行订阅（无换行）按空格切分导致 remark 含空格被截断；**明文（未 base64）订阅体在 `explodeSub` 里会被 `urlSafeBase64Decode` 破坏**（上游 `base64Decode` 对非 base64 字节逐个原样拷贝并重置 4 字符分组，所以 `ss://` 链接里碰巧全落在 base64 字母表的片段会被解码成二进制，密码被毁）；`target=vless/hysteria2` 在 `proxyToSingle` 中的位图互换（`interfaces.cpp:815-825` 传 16/32，而 `GETBIT` 映射是 hysteria2=16、vless=32，两者互换）；`target=tuic` 无对应位（63 位图不含 tuic，故 mixed 输出永不含 tuic）；`/surge2clash` 的 `[Proxy Group]` 策略最终会被 `proxyToClash()` 用空的 `extra_proxy_group` 重建覆盖，只留 `[Proxy]` 里的 DIRECT/REJECT shim；`split` 对结尾分隔符不产生空尾元素等。

> 上面这些行为都在 `test/unit/parser.test.ts`、`test/unit/orchestrator.test.ts`、`test/unit/surge2clash.test.ts` 里有断言锁定，避免被"顺手修掉"而与上游输出不一致。

### 踩坑记录（排查结论）

- **`exclude_remarks` 会吃掉流量节点**：pref 默认 `exclude_remarks = ["(到期|剩余流量|时间|官网|产品)"]`，节点 remark 含"剩余流量"/"到期时间"时该节点会被 `filterNodes` 滤出输出，但它**仍然**参与 `getSubInfoFromNodes` 生成 `Subscription-UserInfo`。所以用一个"只有流量节点"的订阅测流量头会得到 `400 No nodes were found!`，这是上游一致行为，不是 bug。
- **pref 的 `time_rule` 是 `^...$` 锚定的**，无法与 `stream_rule` 同时命中同一条 remark；此时上游仍会输出 `download=0; total=0; expire=...`。
- **`/sub` 的 token 只用于放行 `default_url`**（`interfaces.cpp:368`），不禁用请求自带的 `url=` 参数——API 模式下 `/sub?url=...` 仍可任意抓取订阅，与上游一致。真正做鉴权的是 `/get` `/getlocal` `/readconf` `/updateconf` `/refreshrules` `/flushcache` `/getprofile`。
- **`API_TOKEN` 等环境变量覆盖必须在 `/readconf`、`/updateconf` 之后重新应用**：`readConf()` 会用 pref 里的 `api_access_token` 覆盖内存值，若不重放环境变量，重新载入配置后鉴权会退回 pref 的值（API 模式下表现为 `/getprofile` 正确 token 也 403）。`src/routes/routes.ts` 的 `setEnvOverrideApplier` 负责这一点。
- **`wrangler.jsonc` 的 `[vars]` 优先于同名进程环境变量**：本地要覆盖请用 `npx wrangler dev --var API_TOKEN:xxx`，直接 `$env:API_TOKEN` 无效。

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
