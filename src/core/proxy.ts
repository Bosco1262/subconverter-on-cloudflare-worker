// Port of src/parser/config/proxy.h — core node data model

import { tribool } from "../lib/tribool";

export enum ProxyType {
  Unknown,
  Shadowsocks,
  ShadowsocksR,
  VMess,
  Trojan,
  Snell,
  HTTP,
  HTTPS,
  SOCKS5,
  WireGuard,
  VLESS,
  Hysteria,
  Hysteria2,
  TUIC,
  AnyTLS,
  Mieru,
}

export function getProxyTypeName(type: ProxyType): string {
  switch (type) {
    case ProxyType.Shadowsocks:
      return "SS";
    case ProxyType.ShadowsocksR:
      return "SSR";
    case ProxyType.VMess:
      return "VMess";
    case ProxyType.Trojan:
      return "Trojan";
    case ProxyType.Snell:
      return "Snell";
    case ProxyType.HTTP:
      return "HTTP";
    case ProxyType.HTTPS:
      return "HTTPS";
    case ProxyType.SOCKS5:
      return "SOCKS5";
    case ProxyType.WireGuard:
      return "WireGuard";
    case ProxyType.VLESS:
      return "Vless";
    case ProxyType.Hysteria:
      return "Hysteria";
    case ProxyType.Hysteria2:
      return "Hysteria2";
    case ProxyType.TUIC:
      return "Tuic";
    case ProxyType.AnyTLS:
      return "AnyTLS";
    case ProxyType.Mieru:
      return "Mieru";
    default:
      return "Unknown";
  }
}

export interface Proxy {
  Type: ProxyType;
  Id: number;
  GroupId: number;
  Group: string;
  Remark: string;
  Hostname: string;
  Port: number;
  CongestionControl: string;
  Username: string;
  Password: string;
  EncryptMethod: string;
  Plugin: string;
  PluginOption: string;
  Protocol: string;
  ProtocolParam: string;
  OBFS: string;
  OBFSParam: string;
  UserId: string;
  AlterId: number;
  TransferProtocol: string;
  FakeType: string;
  AuthStr: string;
  IdleSessionCheckInterval: number;
  IdleSessionTimeout: number;
  MinIdleSession: number;
  TLSStr: string;
  TLSSecure: boolean;

  Host: string;
  Path: string;
  Edge: string;

  QUICSecure: string;
  QUICSecret: string;

  UDP: tribool;
  XUDP: tribool;
  TCPFastOpen: tribool;
  AllowInsecure: tribool;
  TLS13: tribool;

  SnellVersion: number;
  ServerName: string;

  SelfIP: string;
  SelfIPv6: string;
  PublicKey: string;
  PrivateKey: string;
  PreSharedKey: string;
  DnsServers: string[];
  Mtu: number;
  AllowedIPs: string;
  KeepAlive: number;
  TestUrl: string;
  ClientId: string;
  Ports: string;
  Auth: string;
  Alpn: string;
  UpMbps: string;
  DownMbps: string;
  Insecure: string;
  Fingerprint: string;
  OBFSPassword: string;
  GRPCServiceName: string;
  GRPCMode: string;
  ShortId: string;
  Flow: string;
  Encryption: string;
  FlowShow: boolean;
  DisableSni: tribool;
  UpSpeed: number;
  DownSpeed: number;
  SNI: string;
  ReduceRtt: tribool;
  UdpRelayMode: string;
  RequestTimeout: number;
  token: string;
  UnderlyingProxy: string;
  AlpnList: string[];
  PacketEncoding: string;
  Multiplexing: string;
  V2rayHttpUpgrade: tribool;
  XHTTPOptions: Record<string, string>;
}

export function newProxy(): Proxy {
  return {
    Type: ProxyType.Unknown,
    Id: 0,
    GroupId: 0,
    Group: "",
    Remark: "",
    Hostname: "",
    Port: 0,
    CongestionControl: "",
    Username: "",
    Password: "",
    EncryptMethod: "",
    Plugin: "",
    PluginOption: "",
    Protocol: "",
    ProtocolParam: "",
    OBFS: "",
    OBFSParam: "",
    UserId: "",
    AlterId: 0,
    TransferProtocol: "",
    FakeType: "",
    AuthStr: "",
    IdleSessionCheckInterval: 30,
    IdleSessionTimeout: 30,
    MinIdleSession: 0,
    TLSStr: "",
    TLSSecure: false,
    Host: "",
    Path: "",
    Edge: "",
    QUICSecure: "",
    QUICSecret: "",
    UDP: new tribool(),
    XUDP: new tribool(),
    TCPFastOpen: new tribool(),
    AllowInsecure: new tribool(),
    TLS13: new tribool(),
    SnellVersion: 0,
    ServerName: "",
    SelfIP: "",
    SelfIPv6: "",
    PublicKey: "",
    PrivateKey: "",
    PreSharedKey: "",
    DnsServers: [],
    Mtu: 0,
    AllowedIPs: "0.0.0.0/0, ::/0",
    KeepAlive: 0,
    TestUrl: "",
    ClientId: "",
    Ports: "",
    Auth: "",
    Alpn: "",
    UpMbps: "",
    DownMbps: "",
    Insecure: "",
    Fingerprint: "",
    OBFSPassword: "",
    GRPCServiceName: "",
    GRPCMode: "",
    ShortId: "",
    Flow: "",
    Encryption: "",
    FlowShow: false,
    DisableSni: new tribool(),
    UpSpeed: 0,
    DownSpeed: 0,
    SNI: "",
    ReduceRtt: new tribool(),
    UdpRelayMode: "native",
    RequestTimeout: 15000,
    token: "",
    UnderlyingProxy: "",
    AlpnList: [],
    PacketEncoding: "",
    Multiplexing: "",
    V2rayHttpUpgrade: new tribool(),
    XHTTPOptions: {},
  };
}

export const SS_DEFAULT_GROUP = "SSProvider";
export const SSR_DEFAULT_GROUP = "SSRProvider";
export const V2RAY_DEFAULT_GROUP = "V2RayProvider";
export const SOCKS_DEFAULT_GROUP = "SocksProvider";
export const HTTP_DEFAULT_GROUP = "HTTPProvider";
export const TROJAN_DEFAULT_GROUP = "TrojanProvider";
export const SNELL_DEFAULT_GROUP = "SnellProvider";
export const WG_DEFAULT_GROUP = "WireGuardProvider";
export const XRAY_DEFAULT_GROUP = "XRayProvider";
export const HYSTERIA_DEFAULT_GROUP = "HysteriaProvider";
export const HYSTERIA2_DEFAULT_GROUP = "Hysteria2Provider";
export const TUIC_DEFAULT_GROUP = "TuicProvider";
export const ANYTLS_DEFAULT_GROUP = "AnyTLSProvider";
export const MIERU_DEFAULT_GROUP = "MieruProvider";
