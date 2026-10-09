// Port of src/parser/subparser.cpp — shared helpers and *Construct functions (lines 1-444)

import { tribool } from "../../lib/tribool";
import { trim, trimOf, toInt, getUrlArg, split, splitFirst, join, startsWith } from "../../lib/string";
import { urlDecode } from "../../lib/urlencode";
import { regFind, regGetAllMatch, regMatch, regReplace } from "../../lib/regex";
import { newProxy, Proxy, ProxyType, SS_DEFAULT_GROUP } from "../proxy";

// C++ `s.substr(0, s.rfind(':'))` paired with `s.substr(s.rfind(':') + 1)`: `rfind` returns npos when
// the value has no colon, and `substr(0, npos)` is the WHOLE string (while `substr(npos + 1)` is
// `substr(0)`, also the whole string). JS `substring(0, -1)` collapses to "" instead, which silently
// dropped hostnames. Returns [host, portText] with both equal to the input when there is no colon.
export function splitHostPortRfind(value: string): [string, string] {
  const pos = value.lastIndexOf(":");
  if (pos === -1) return [value, value];
  return [value.substring(0, pos), value.substring(pos + 1)];
}

export function isIPv4(address: string): boolean {
  return regMatch(address, "^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}$");
}

export function isIPv6(address: string): boolean {
  const regLists = [
    "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
    "^((?:[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::((?:([0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4})?)$",
    "^(::(?:[0-9A-Fa-f]{1,4})(?::[0-9A-Fa-f]{1,4}){5})|((?:[0-9A-Fa-f]{1,4})(?::[0-9A-Fa-f]{1,4}){5}::)$",
  ];
  for (const reg of regLists) {
    if (regMatch(address, reg)) return true;
  }
  return false;
}

export function isLink(url: string): boolean {
  return startsWith(url, "https://") || startsWith(url, "http://") || startsWith(url, "data:");
}

export const ss_ciphers = [
  "rc4-md5", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb",
  "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "camellia-128-cfb",
  "camellia-192-cfb", "camellia-256-cfb", "bf-cfb", "chacha20-ietf-poly1305",
  "xchacha20-ietf-poly1305", "salsa20", "chacha20", "chacha20-ietf", "2022-blake3-aes-128-gcm",
  "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "2022-blake3-chacha12-poly1305",
  "2022-blake3-chacha8-poly1305",
];

export const ssr_ciphers = [
  "none", "table", "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
  "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "bf-cfb", "camellia-128-cfb",
  "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb",
  "seed-cfb", "salsa20", "chacha20", "chacha20-ietf",
];

export const xhttp_option_keys = [
  "mode",
  "no-grpc-header",
  "no-sse-header",
  "x-padding-bytes",
  "x-padding-obfs-mode",
  "x-padding-key",
  "x-padding-header",
  "x-padding-placement",
  "x-padding-method",
  "uplink-http-method",
  "session-placement",
  "session-key",
  "seq-placement",
  "seq-key",
  "uplink-data-placement",
  "uplink-data-key",
  "uplink-chunk-size",
  "sc-max-each-post-bytes",
  "sc-min-posts-interval-ms",
  "sc-max-buffered-posts",
  "sc-stream-up-server-secs",
];

export function isXHTTPOptionKey(key: string): boolean {
  return xhttp_option_keys.includes(key);
}

export function normalizeXHTTPOptionKey(key: string): string {
  let result = "";
  for (let i = 0; i < key.length; i++) {
    const current = key.charCodeAt(i);
    if (key[i] === "_") {
      if (result.length > 0 && result[result.length - 1] !== "-") result += "-";
    } else if (current >= 65 && current <= 90) {
      const prevIsLowerOrDigit =
        i > 0 &&
        ((key.charCodeAt(i - 1) >= 97 && key.charCodeAt(i - 1) <= 122) ||
          (key.charCodeAt(i - 1) >= 48 && key.charCodeAt(i - 1) <= 57));
      const acronymEnds =
        i > 0 &&
        i + 1 < key.length &&
        key.charCodeAt(i - 1) >= 65 &&
        key.charCodeAt(i - 1) <= 90 &&
        key.charCodeAt(i + 1) >= 97 &&
        key.charCodeAt(i + 1) <= 122;
      if (result.length > 0 && result[result.length - 1] !== "-" && (prevIsLowerOrDigit || acronymEnds)) result += "-";
      result += key[i].toLowerCase();
    } else {
      result += key[i];
    }
  }
  return result;
}

// rapidjson GetMember on a JSON value
export function jsonScalarToString(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (Number.isInteger(value)) return String(value);
    // C++ std::to_string(double) → 6 decimals
    return value.toFixed(6);
  }
  return "";
}

// GetMember(json, key) — "" when missing
export function getMember(json: Record<string, unknown> | undefined | null, member: string): string {
  if (!json || typeof json !== "object") return "";
  if (Object.prototype.hasOwnProperty.call(json, member)) return jsonScalarToString(json[member]);
  return "";
}

// GetMember(json, key, target) — only overwrites when non-empty
export function getMemberTo(json: Record<string, unknown> | undefined | null, member: string, target: { v: string }): void {
  const ret = getMember(json, member);
  if (ret.length > 0) target.v = ret;
}

// rapidjson `value >> string` semantics for arbitrary values
export function jsonToString(value: unknown): string {
  return jsonScalarToString(value);
}

export function readXHTTPExtraOptions(addition: string, node: Proxy): void {
  const extra = urlDecode(getUrlArg(addition, "extra"));
  if (extra.length === 0) return;
  let json: unknown;
  try {
    json = JSON.parse(extra);
  } catch {
    return;
  }
  if (!json || typeof json !== "object" || Array.isArray(json)) return;
  for (const [name, val] of Object.entries(json as Record<string, unknown>)) {
    const key = normalizeXHTTPOptionKey(name);
    const value = jsonScalarToString(val);
    if (isXHTTPOptionKey(key) && value.length > 0) node.XHTTPOptions[key] = value;
  }
}

export function removeBrackets(input: string): string {
  const left = input.indexOf("[");
  const right = input.indexOf("]");
  if (left !== -1 && right !== -1 && right > left) {
    return input.substring(0, left) + input.substring(left + 1, right) + input.substring(right + 1);
  }
  return input;
}

export function extractRemark(link: { v: string }, remark: { v: string }): void {
  let pos = link.v.lastIndexOf("#");
  if (pos !== -1) {
    remark.v = urlDecode(link.v.substring(pos + 1));
    link.v = link.v.substring(0, pos);
  }
  pos = link.v.indexOf("#");
  if (pos !== -1) {
    link.v = link.v.substring(0, pos);
  }
}

export function getUrlAlpnList(addition: string): string[] {
  const result: string[] = [];
  const alpn = urlDecode(getUrlArg(addition, "alpn"));
  if (alpn.length === 0) return result;
  for (let item of split(alpn, ",")) {
    item = trim(item);
    if (item.length > 0) result.push(item);
  }
  return result;
}

export function getUrlAlpn(addition: string): string {
  return join(getUrlAlpnList(addition), ",");
}

function commonConstruct(
  node: Proxy,
  type: ProxyType,
  group: string,
  remarks: string,
  server: string,
  port: string,
  udp: tribool,
  tfo: tribool,
  scv: tribool,
  tls13: tribool,
  underlyingProxy: string,
): void {
  node.Type = type;
  node.Group = group;
  node.Remark = remarks;
  node.Hostname = removeBrackets(server);
  node.Port = toInt(port);
  node.UDP = udp;
  node.TCPFastOpen = tfo;
  node.AllowInsecure = scv;
  node.TLS13 = tls13;
  node.UnderlyingProxy = underlyingProxy;
}

export function vmessConstruct(
  node: Proxy, group: string, remarks: string, add: string, port: string, type: string, id: string, aid: string,
  net: string, cipher: string, path: string, host: string, edge: string, tls: string, sni: string,
  alpnList: string[], udp = new tribool(), tfo = new tribool(), scv = new tribool(), tls13 = new tribool(),
  underlyingProxy = "",
): void {
  commonConstruct(node, ProxyType.VMess, group, remarks, add, port, udp, tfo, scv, tls13, underlyingProxy);
  node.UserId = id.length === 0 ? "00000000-0000-0000-0000-000000000000" : id;
  node.AlterId = toInt(aid);
  node.EncryptMethod = cipher;
  node.TransferProtocol = net.length === 0 ? "tcp" : net;
  node.Edge = edge;
  node.ServerName = sni;
  node.AlpnList = alpnList;
  if (net === "quic") {
    node.QUICSecure = host;
    node.QUICSecret = path;
  } else {
    node.Host = host.length === 0 && !isIPv4(add) && !isIPv6(add) ? add : trim(host);
    node.Path = path.length === 0 ? "/" : trim(path);
  }
  node.FakeType = type;
  node.TLSSecure = tls === "tls";
}

export function ssrConstruct(
  node: Proxy, group: string, remarks: string, server: string, port: string, protocol: string, method: string,
  obfs: string, password: string, obfsparam: string, protoparam: string, udp = new tribool(), tfo = new tribool(),
  scv = new tribool(), underlyingProxy = "",
): void {
  commonConstruct(node, ProxyType.ShadowsocksR, group, remarks, server, port, udp, tfo, scv, new tribool(), underlyingProxy);
  node.Password = password;
  node.EncryptMethod = method;
  node.Protocol = protocol;
  node.ProtocolParam = protoparam;
  node.OBFS = obfs;
  node.OBFSParam = obfsparam;
}

export function ssConstruct(
  node: Proxy, group: string, remarks: string, server: string, port: string, password: string, method: string,
  plugin: string, pluginopts: string, udp = new tribool(), tfo = new tribool(), scv = new tribool(),
  tls13 = new tribool(), underlyingProxy = "",
): void {
  commonConstruct(node, ProxyType.Shadowsocks, group, remarks, server, port, udp, tfo, scv, tls13, underlyingProxy);
  node.Password = password;
  node.EncryptMethod = method;
  node.Plugin = plugin;
  node.PluginOption = pluginopts;
}

export function socksConstruct(
  node: Proxy, group: string, remarks: string, server: string, port: string, username: string, password: string,
  udp = new tribool(), tfo = new tribool(), scv = new tribool(), underlyingProxy = "",
): void {
  commonConstruct(node, ProxyType.SOCKS5, group, remarks, server, port, udp, tfo, scv, new tribool(), underlyingProxy);
  node.Username = username;
  node.Password = password;
}

export function httpConstruct(
  node: Proxy, group: string, remarks: string, server: string, port: string, username: string, password: string,
  tls: boolean, tfo = new tribool(), scv = new tribool(), tls13 = new tribool(), underlyingProxy = "",
): void {
  commonConstruct(node, tls ? ProxyType.HTTPS : ProxyType.HTTP, group, remarks, server, port, new tribool(), tfo, scv, tls13, underlyingProxy);
  node.Username = username;
  node.Password = password;
  node.TLSSecure = tls;
}

export function trojanConstruct(
  node: Proxy, group: string, remarks: string, server: string, port: string, password: string, network: string,
  host: string, path: string, fp: string, sni: string, alpnList: string[], tlssecure: boolean,
  udp = new tribool(), tfo = new tribool(), scv = new tribool(), tls13 = new tribool(), underlyingProxy = "",
): void {
  commonConstruct(node, ProxyType.Trojan, group, remarks, server, port, udp, tfo, scv, tls13, underlyingProxy);
  node.Password = password;
  node.Host = host;
  node.TLSSecure = tlssecure;
  node.TransferProtocol = network.length === 0 ? "tcp" : network;
  node.Path = path;
  node.Fingerprint = fp;
  node.ServerName = sni;
  node.AlpnList = alpnList;
}

export function snellConstruct(
  node: Proxy, group: string, remarks: string, server: string, port: string, password: string, obfs: string,
  host: string, version = 0, udp = new tribool(), tfo = new tribool(), scv = new tribool(), underlyingProxy = "",
): void {
  commonConstruct(node, ProxyType.Snell, group, remarks, server, port, udp, tfo, scv, new tribool(), underlyingProxy);
  node.Password = password;
  node.OBFS = obfs;
  node.Host = host;
  node.SnellVersion = version;
}

export function wireguardConstruct(
  node: Proxy, group: string, remarks: string, server: string, port: string, selfIp: string, selfIpv6: string,
  privKey: string, pubKey: string, psk: string, dns: string[], mtu: string, keepalive: string, testUrl: string,
  clientId: string, udp: tribool, underlyingProxy: string,
): void {
  commonConstruct(node, ProxyType.WireGuard, group, remarks, server, port, udp, new tribool(), new tribool(), new tribool(), underlyingProxy);
  node.SelfIP = selfIp;
  node.SelfIPv6 = selfIpv6;
  node.PrivateKey = privKey;
  node.PublicKey = pubKey;
  node.PreSharedKey = psk;
  node.DnsServers = dns;
  node.Mtu = toInt(mtu);
  node.KeepAlive = toInt(keepalive);
  node.TestUrl = testUrl;
  node.ClientId = clientId;
}

export function hysteriaConstruct(
  node: Proxy, group: string, remarks: string, add: string, port: string, type: string, auth: string,
  authStr: string, host: string, up: string, down: string, alpn: string, obfsParam: string, insecure: string,
  ports: string, sni: string, udp = new tribool(), tfo = new tribool(), scv = new tribool(),
  tls13 = new tribool(), underlyingProxy = "",
): void {
  commonConstruct(node, ProxyType.Hysteria, group, remarks, add, port, udp, tfo, scv, tls13, underlyingProxy);
  node.Auth = auth;
  node.Host = host.length === 0 && !isIPv4(add) && !isIPv6(add) ? add : trim(host);
  node.UpMbps = up;
  node.DownMbps = down;
  node.Alpn = alpn;
  node.OBFSParam = obfsParam;
  node.Insecure = insecure;
  node.FakeType = type;
  node.AuthStr = authStr;
  node.Ports = ports;
  node.ServerName = sni;
}

export function hysteria2Construct(
  node: Proxy, group: string, remarks: string, add: string, port: string, password: string, host: string,
  up: string, down: string, alpn: string, obfsParam: string, obfsPassword: string, sni: string, publicKey: string,
  fingerprint: string, ports: string, udp: tribool, tfo: tribool, scv: tribool, underlyingProxy = "",
): void {
  commonConstruct(node, ProxyType.Hysteria2, group, remarks, add, port, udp, tfo, scv, new tribool(), underlyingProxy);
  node.Password = password;
  node.Host = host.length === 0 && !isIPv4(add) && !isIPv6(add) ? add : trim(host);
  node.UpMbps = up;
  node.DownMbps = down;
  node.Alpn = alpn;
  node.OBFSParam = obfsParam;
  node.OBFSPassword = obfsPassword;
  node.ServerName = sni;
  node.PublicKey = publicKey;
  node.Fingerprint = fingerprint;
  node.Ports = ports;
}

export function anyTlSConstruct(
  node: Proxy, group: string, remarks: string, port: string, password: string, host: string, alpnList: string[],
  fingerprint: string, sni: string, udp: tribool, tfo: tribool, scv: tribool, tls13: tribool,
  underlyingProxy = "", idleSessionCheckInterval = 30, idleSessionTimeout = 30, minIdleSession = 0,
): void {
  commonConstruct(node, ProxyType.AnyTLS, group, remarks, host, port, udp, tfo, scv, tls13, underlyingProxy);
  node.Host = trim(host);
  node.Password = password;
  node.AlpnList = alpnList;
  node.SNI = sni;
  node.Fingerprint = fingerprint;
  node.IdleSessionCheckInterval = idleSessionCheckInterval;
  node.IdleSessionTimeout = idleSessionTimeout;
  node.MinIdleSession = minIdleSession;
}

export function mieruConstruct(
  node: Proxy, group: string, remarks: string, port: string, password: string, host: string, ports: string,
  username: string, multiplexing: string, transferProtocol: string, udp: tribool, tfo: tribool, scv: tribool,
  tls13: tribool, underlyingProxy: string,
): void {
  commonConstruct(node, ProxyType.Mieru, group, remarks, host, port, udp, tfo, scv, tls13, underlyingProxy);
  node.Host = trim(host);
  node.Password = password;
  node.Ports = ports;
  node.TransferProtocol = transferProtocol.length === 0 ? "TCP" : trim(transferProtocol);
  node.Username = username;
  node.Multiplexing = multiplexing.length === 0 ? "MULTIPLEXING_LOW" : trim(multiplexing);
}

export function vlessConstruct(
  node: Proxy, group: string, remarks: string, add: string, port: string, type: string, id: string, aid: string,
  net: string, cipher: string, flow: string, mode: string, path: string, host: string, edge: string, tls: string,
  pbk: string, sid: string, fp: string, sni: string, alpnList: string[], packetEncoding: string, encryption: string,
  udp = new tribool(), tfo = new tribool(), scv = new tribool(), tls13 = new tribool(), underlyingProxy = "",
  v2rayHttpUpgrade = new tribool(),
): void {
  commonConstruct(node, ProxyType.VLESS, group, remarks, add, port, udp, tfo, scv, tls13, underlyingProxy);
  node.UserId = id.length === 0 ? "00000000-0000-0000-0000-000000000000" : id;
  node.AlterId = toInt(aid);
  node.EncryptMethod = cipher;
  node.TransferProtocol = net.length === 0 ? "tcp" : type === "http" ? "http" : net;
  node.Edge = edge;
  node.Flow = flow;
  node.Encryption = encryption;
  node.FakeType = type;
  node.TLSSecure = tls === "tls" || tls === "xtls" || tls === "reality";
  node.PublicKey = pbk;
  node.ShortId = sid;
  node.Fingerprint = fp;
  node.ServerName = sni;
  node.AlpnList = alpnList;
  node.PacketEncoding = packetEncoding;
  node.TLSStr = tls;
  switch (net) {
    case "grpc":
      node.Host = host;
      node.GRPCMode = mode.length === 0 ? "gun" : mode;
      node.GRPCServiceName = path.length === 0 ? "/" : urlDecode(trim(path));
      break;
    case "quic":
      node.Host = host;
      node.QUICSecret = path.length === 0 ? "/" : trim(path);
      break;
    default:
      node.Host = host.length === 0 && !isIPv4(add) && !isIPv6(add) ? add : trim(host);
      node.Path = path.length === 0 ? "/" : urlDecode(trim(path));
      node.V2rayHttpUpgrade = v2rayHttpUpgrade;
      break;
  }
}

export function tuicConstruct(
  node: Proxy, group: string, remarks: string, add: string, port: string, password: string, congestionControl: string,
  alpn: string, sni: string, uuid: string, udpRelayMode: string, token: string, udp = new tribool(), tfo = new tribool(),
  scv = new tribool(), reduceRtt = new tribool(), disableSni = new tribool(), requestTimeout = 15000, underlyingProxy = "",
): void {
  commonConstruct(node, ProxyType.TUIC, group, remarks, add, port, udp, tfo, scv, new tribool(), underlyingProxy);
  node.Password = password;
  node.Alpn = alpn;
  node.ServerName = sni;
  node.CongestionControl = congestionControl;
  node.ReduceRtt = reduceRtt;
  node.DisableSni = disableSni;
  node.UserId = uuid;
  node.UdpRelayMode = udpRelayMode;
  node.token = token;
  node.RequestTimeout = requestTimeout;
}

// peer = (public-key = ..., endpoint = ..., ...) — Cloudflare WARP style
export function parsePeers(node: Proxy, data: string): void {
  const peers = regGetAllMatch(data, "\\((.*?)\\)", true);
  if (peers.length === 0) return;
  const peer = peers[0];
  const peerdata = regGetAllMatch(peer, "([a-z-]+) ?= ?([^\" ),]+|\".*?\"),? ?", true);
  if (peerdata.length % 2 !== 0) return;
  for (let i = 0; i < peerdata.length; i += 2) {
    const key = peerdata[i];
    const val = peerdata[i + 1];
    switch (key) {
      case "public-key":
        node.PublicKey = val;
        break;
      case "endpoint": {
        // C++ `val.substr(0, val.rfind(':'))` / `substr(rfind(':') + 1)`: rfind yields npos when the
        // value has no colon, and substr(0, npos) is the WHOLE string (substr(npos+1) == substr(0)
        // too), so upstream keeps the hostname and gets port 0. JS substring(0, -1) collapses to ""
        // and silently dropped the hostname.
        const hp = splitHostPortRfind(val);
        node.Hostname = hp[0];
        node.Port = toInt(hp[1]);
        break;
      }
      case "client-id":
        node.ClientId = val;
        break;
      case "allowed-ips":
        node.AllowedIPs = trimOf(val, '"');
        break;
    }
  }
}
