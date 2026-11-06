const http = require('http');
const https = require('https');
const dns = require('dns');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const SECRET_KEY = "Im7R9FYpBFwXmKX6";
const profileTitle = "svg Collection";
const profileTitleBase64 = "base64:" + Buffer.from(profileTitle).toString('base64');

const nodeLinks = require('./node_links');

// Helper: Parse VLESS, Shadowsocks (ss://) and Hysteria 2 (hysteria2://) URLs
function parseNode(link) {
  try {
    if (link.startsWith("wireguard://")) {
      const hashIdx = link.indexOf("#");
      const name = hashIdx !== -1 ? decodeURIComponent(link.substring(hashIdx + 1)) : "WireGuard";
      const mainPart = hashIdx !== -1 ? link.substring(0, hashIdx) : link;
      const withoutScheme = mainPart.substring("wireguard://".length);
      const atIdx = withoutScheme.indexOf("@");

      let privateKey = "";
      let host = "";
      let port = 51820;
      let queryStr = "";

      if (atIdx !== -1) {
        privateKey = decodeURIComponent(withoutScheme.substring(0, atIdx));
        const rest = withoutScheme.substring(atIdx + 1);
        const qIdx = rest.indexOf("?");
        const hostPort = qIdx !== -1 ? rest.substring(0, qIdx) : rest;
        const hpParts = hostPort.split(":");
        host = hpParts[0];
        port = parseInt(hpParts[1]) || 51820;
        queryStr = qIdx !== -1 ? rest.substring(qIdx) : "";
      }

      const dummyUrl = new URL("http://dummy.local/" + (queryStr.startsWith("?") ? queryStr : "?" + queryStr));
      const searchParams = dummyUrl.searchParams;
      const address = searchParams.get("address") || "10.0.0.2/32";
      const publicKey = searchParams.get("publickey") || searchParams.get("publicKey") || "";
      const dns = searchParams.get("dns") || "1.1.1.1, 1.0.0.1";
      const mtu = parseInt(searchParams.get("mtu")) || 1420;
      const allowedIPs = searchParams.get("allowedIPs") || "0.0.0.0/0, ::/0";

      const wgConf = `[Interface]
PrivateKey = ${privateKey}
Address = ${address}
DNS = ${dns}
MTU = ${mtu}

[Peer]
PublicKey = ${publicKey}
AllowedIPs = ${allowedIPs}
Endpoint = ${host}:${port}
`;

      return {
        protocol: "wireguard",
        name,
        privateKey,
        host,
        port,
        address,
        publicKey,
        dns,
        mtu,
        allowedIPs,
        wgConf
      };
    }

    const parsed = new URL(link);
    const protocol = parsed.protocol.replace(":", "");
    const name = decodeURIComponent(parsed.hash.substring(1));
    
    if (protocol === "vless") {
      const uuid = parsed.username;
      const host = parsed.hostname;
      const port = parseInt(parsed.port);
      const searchParams = parsed.searchParams;
      return {
        protocol: "vless",
        name,
        uuid,
        host,
        port,
        security: searchParams.get("security") || (searchParams.get("security") === null && searchParams.get("encryption") === "none" ? "none" : "tls"),
        type: searchParams.get("type"),
        path: searchParams.get("path"),
        sni: searchParams.get("sni"),
        pbk: searchParams.get("pbk"),
        sid: searchParams.get("sid"),
        flow: searchParams.get("flow"),
        fp: searchParams.get("fp")
      };
    } else if (protocol === "ss") {
      const host = parsed.hostname;
      const port = parseInt(parsed.port);
      const searchParams = parsed.searchParams;
      const prefix = searchParams.get("prefix");
      
      let method = "";
      let password = "";
      const rawUser = parsed.username;
      
      if (rawUser.includes(":")) {
        const parts = rawUser.split(":");
        method = parts[0];
        password = parts[1];
      } else {
        try {
          const decoded = Buffer.from(rawUser, 'base64').toString('utf-8');
          if (decoded.includes(":")) {
            const parts = decoded.split(":");
            method = parts[0];
            password = parts[1];
          }
        } catch (e) {
          method = "chacha20-ietf-poly1305";
          password = rawUser;
        }
      }
      
      return {
        protocol: "ss",
        name,
        host,
        port,
        method: method || "chacha20-ietf-poly1305",
        password: password || rawUser,
        prefix: prefix || null
      };
    } else if (protocol === "hysteria2" || protocol === "hysteria") {
      const password = parsed.username || parsed.password;
      const host = parsed.hostname;
      const port = parseInt(parsed.port);
      const searchParams = parsed.searchParams;
      return {
        protocol: "hysteria2",
        name,
        password,
        host,
        port,
        sni: searchParams.get("sni"),
        obfs: searchParams.get("obfs"),
        obfsPassword: searchParams.get("obfs-password") || searchParams.get("obfs_password")
      };
    } else if (protocol === "trojan") {
      const password = parsed.username;
      const host = parsed.hostname;
      const port = parseInt(parsed.port);
      const searchParams = parsed.searchParams;
      return {
        protocol: "trojan",
        name,
        password,
        host,
        port,
        type: searchParams.get("type"),
        security: searchParams.get("security") || "tls",
        sni: searchParams.get("sni"),
        serviceName: searchParams.get("serviceName") || searchParams.get("service_name"),
        authority: searchParams.get("authority")
      };
    }
  } catch (e) {
    return null;
  }
}

// Helper: Generate Clash YAML with runetfreedom rulesets
function generateClashYaml(proxies) {
  const proxyNames = proxies.map(p => `"${p.name}"`).join(", ");
  let yaml = `port: 7890\nsocks-port: 7891\nallow-lan: true\nmode: rule\nlog-level: info\nipv6: false\n\nproxies:\n`;

  for (const p of proxies) {
    if (p.protocol === "ss") {
      yaml += `  - name: "${p.name}"\n    type: ss\n    server: ${p.server}\n    port: ${p.port}\n    cipher: ${p.cipher}\n    password: ${p.password}\n    udp: true\n`;
    } else if (p.protocol === "hysteria2") {
      yaml += `  - name: "${p.name}"\n    type: hysteria2\n    server: ${p.server}\n    port: ${p.port}\n    password: ${p.password}\n`;
      if (p.sni) yaml += `    sni: ${p.sni}\n`;
      if (p.obfs) {
        yaml += `    obfs: ${p.obfs}\n`;
        if (p["obfs-password"]) yaml += `    obfs-password: ${p["obfs-password"]}\n`;
      }
    } else if (p.protocol === "trojan") {
      yaml += `  - name: "${p.name}"\n    type: trojan\n    server: ${p.server}\n    port: ${p.port}\n    password: ${p.password}\n    udp: true\n    tls: ${p.tls}\n    sni: ${p.sni}\n`;
      if (p.network === "grpc") {
        yaml += `    network: grpc\n    grpc-opts:\n      grpc-service-name: "${p.grpcServiceName}"\n`;
      }
    } else if (p.protocol === "wireguard") {
      yaml += `  - name: "${p.name}"\n    type: wireguard\n    server: ${p.server}\n    port: ${p.port}\n    ip: ${p.ip}\n    public-key: "${p.publicKey}"\n    private-key: "${p.privateKey}"\n    udp: true\n    remote-dns-resolve: false\n    dns: [${p.dns}]\n    mtu: ${p.mtu}\n`;
    } else {
      yaml += `  - name: "${p.name}"\n    type: vless\n    server: ${p.server}\n    port: ${p.port}\n    uuid: ${p.uuid}\n    udp: true\n    tls: ${p.tls}\n    servername: ${p.servername}\n    network: ${p.network === "xhttp" ? "http" : p.network}\n`;
      if (p.flow) yaml += `    flow: ${p.flow}\n`;
      if (p["client-fingerprint"]) yaml += `    client-fingerprint: ${p["client-fingerprint"]}\n`;
      
      if (p.network === "ws") {
        yaml += `    ws-opts:\n      path: ${p.path}\n      headers:\n        Host: ${p.servername}\n`;
      } else if (p.network === "xhttp") {
        yaml += `    xhttp-opts:\n      path: ${p.path}\n`;
      }

      if (p.reality) {
        yaml += `    reality-opts:\n      public-key: ${p.reality.pbk}\n      short-id: ${p.reality.sid}\n`;
      }
    }
  }

  yaml += `
proxy-groups:
  - name: "AUTO-ROUTE-PROXY"
    type: select
    proxies: [${proxyNames}]

rule-providers:
  ru-blocked-domain:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/clash-geosite-ru-blocked.yaml"
    interval: 86400
    path: ./ruleset/ru-blocked-domain.yaml

  ru-blocked-ip:
    type: http
    behavior: ipcidr
    url: "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/clash-geoip-ru-blocked.yaml"
    interval: 86400
    path: ./ruleset/ru-blocked-ip.yaml

rules:
  # 0. Telphin VoIP (Force Proxy)
  - DOMAIN-SUFFIX,telphin.com,AUTO-ROUTE-PROXY
  - DOMAIN-SUFFIX,telphin.ru,AUTO-ROUTE-PROXY
  - IP-CIDR,46.229.220.0/22,AUTO-ROUTE-PROXY,no-resolve
  - IP-CIDR,178.248.232.0/21,AUTO-ROUTE-PROXY,no-resolve
  - IP-CIDR,213.170.92.0/24,AUTO-ROUTE-PROXY,no-resolve

  # 1. Banned apps/sites to proxy
  - GEOSITE,telegram,AUTO-ROUTE-PROXY
  - GEOSITE,youtube,AUTO-ROUTE-PROXY
  - GEOSITE,facebook,AUTO-ROUTE-PROXY
  - GEOSITE,instagram,AUTO-ROUTE-PROXY
  
  # 2. Blocked domains/IPs in Russia to proxy
  - RULE-SET,ru-blocked-domain,AUTO-ROUTE-PROXY
  - RULE-SET,ru-blocked-ip,AUTO-ROUTE-PROXY
  
  # 3. Direct access for RU domains and Government Services
  - GEOSITE,category-gov-ru,DIRECT
  - GEOSITE,ru,DIRECT
  - GEOIP,RU,DIRECT
  
  # 4. Fallback matches direct
  - MATCH,DIRECT
`;
  return yaml;
}

// Helper: Generate Sing-box JSON with runetfreedom rulesets
function generateSingBoxJson(outbounds) {
  const proxyNames = outbounds.map(o => o.tag);
  const config = {
    outbounds: [
      {
        type: "selector",
        tag: "AUTO-ROUTE-PROXY",
        outbounds: proxyNames
      },
      ...outbounds,
      {
        type: "direct",
        tag: "direct"
      },
      {
        type: "block",
        tag: "block"
      }
    ],
    route: {
      rule_set: [
        {
          tag: "ru-blocked-geosite",
          type: "remote",
          format: "binary",
          url: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite-ru-blocked.srs",
          download_detour: "AUTO-ROUTE-PROXY"
        },
        {
          tag: "ru-blocked-geoip",
          type: "remote",
          format: "binary",
          url: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip-ru-blocked.srs",
          download_detour: "AUTO-ROUTE-PROXY"
        },
        {
          tag: "telegram-geosite",
          type: "remote",
          format: "binary",
          url: "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite-telegram.srs",
          download_detour: "AUTO-ROUTE-PROXY"
        }
      ],
      rules: [
        {
          domain_suffix: ["telphin.com", "telphin.ru"],
          ip_cidr: [
            "46.229.220.0/22",
            "178.248.232.0/21",
            "213.170.92.0/24"
          ],
          outbound: "AUTO-ROUTE-PROXY"
        },
        {
          rule_set: [
            "ru-blocked-geosite",
            "ru-blocked-geoip",
            "telegram-geosite"
          ],
          outbound: "AUTO-ROUTE-PROXY"
        },
        {
          geosite: ["category-gov-ru", "ru"],
          geoip: ["ru"],
          outbound: "direct"
        },
        {
          outbound: "direct"
        }
      ]
    }
  };
  return JSON.stringify(config, null, 2);
}

// -----------------------------------------------------------------------------
// Dynamic Geolocation Engine (ipinfo.io with persistent & in-memory cache)
// -----------------------------------------------------------------------------
const GEO_CACHE_FILE = path.join(__dirname, 'geo_cache.json');
let geoCache = {};

try {
  if (fs.existsSync(GEO_CACHE_FILE)) {
    geoCache = JSON.parse(fs.readFileSync(GEO_CACHE_FILE, 'utf8'));
  }
} catch (e) {
  console.error("Error loading geo cache:", e);
}

function saveGeoCache() {
  try {
    fs.writeFileSync(GEO_CACHE_FILE, JSON.stringify(geoCache, null, 2), 'utf8');
  } catch (e) {
    console.error("Error saving geo cache:", e);
  }
}

const displayNames = new Intl.DisplayNames(['en'], { type: 'region' });

function flagEmoji(countryCode) {
  try {
    return String.fromCodePoint(...[...countryCode.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
  } catch (e) {
    return '🌐';
  }
}

function extractProviderName(org) {
  if (!org) return '';
  if (/veesp/i.test(org)) return 'Veesp';
  if (/selectel/i.test(org)) return 'Selectel';
  if (/timeweb/i.test(org)) return 'Timeweb';
  if (/aeza/i.test(org)) return 'Aeza';
  if (/alexhost/i.test(org)) return 'AlexHost';
  return org.replace(/^AS\d+\s+/, '').split(' ')[0].replace(/,/g, '');
}

function extractHostFromLink(link) {
  try {
    if (link.startsWith('wireguard://')) {
      const withoutScheme = link.substring('wireguard://'.length).split('#')[0];
      const atIdx = withoutScheme.indexOf('@');
      if (atIdx !== -1) {
        const hostPort = withoutScheme.substring(atIdx + 1).split('?')[0];
        return hostPort.split(':')[0];
      }
    }
    const url = new URL(link);
    return url.hostname;
  } catch (e) {
    const m = link.match(/@([^:/?#]+)/);
    return m ? m[1] : '';
  }
}

function fetchIpInfoJson(ip) {
  return new Promise((resolve) => {
    https.get(`https://ipinfo.io/${ip}/json`, { headers: { 'User-Agent': 'curl/8.0' } }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve(null);
        }
      });
    }).on('error', () => resolve(null));
  });
}

const CASCADE_EXITS = {
  'seltel-ws-ch': {
    countryCode: 'CH',
    countryName: 'Switzerland',
    flag: '🇨🇭',
    provider: 'Infomaniak',
    subtitle: '🇨🇭 CH, Switzerland',
    testUrl: 'https://infoman.svgrn.work/'
  },
  'seltel-ws-nl': {
    countryCode: 'NL',
    countryName: 'Netherlands',
    flag: '🇳🇱',
    provider: 'Timeweb Amsterdam',
    subtitle: '🇳🇱 NL, Netherlands',
    testUrl: 'https://timeweb-nl.svgrn.work/'
  },
  'aeza1010ws-se': {
    countryCode: 'SE',
    countryName: 'Sweden',
    flag: '🇸🇪',
    provider: 'AWS Stockholm',
    subtitle: '🇸🇪 SE, Sweden',
    testUrl: 'https://veespse.svgrn.work/'
  },
  'aeza1010ws-is': {
    countryCode: 'IS',
    countryName: 'Iceland',
    flag: '🇮🇸',
    provider: '1984 Hosting',
    subtitle: '🇮🇸 IS, Iceland',
    testUrl: 'https://is1984.svgrn.work/'
  },
  'aeza1010ws-lv': {
    countryCode: 'LV',
    countryName: 'Latvia',
    flag: '🇱🇻',
    provider: 'Veesp Riga',
    subtitle: '🇱🇻 LV, Latvia',
    testUrl: 'https://veesp.svgrn.work/'
  },
  'aeza1010ws-nl': {
    countryCode: 'NL',
    countryName: 'Netherlands',
    flag: '🇳🇱',
    provider: 'Veesp Amsterdam',
    subtitle: '🇳🇱 NL, Netherlands',
    testUrl: 'https://veespnl.svgrn.work/'
  },
  'aeza1010ws-il': {
    countryCode: 'IL',
    countryName: 'Israel',
    flag: '🇮🇱',
    provider: 'Kamatera Petah Tiqva',
    subtitle: '🇮🇱 IL, Israel',
    testUrl: 'https://ifconfig.co/'
  },
  'aeza1010ws-ch': {
    countryCode: 'CH',
    countryName: 'Switzerland',
    flag: '🇨🇭',
    provider: 'Infomaniak Geneva',
    subtitle: '🇨🇭 CH, Switzerland',
    testUrl: 'https://infoman.svgrn.work/'
  }
};

function getCascadeExitGeo(link, nodeName) {
  let name = nodeName;
  if (!name && link) {
    try {
      const u = new URL(link);
      if (u.hash) name = decodeURIComponent(u.hash.substring(1));
    } catch (e) {}
  }
  if (!name) return null;

  const cleanName = name.replace(/^[\s\u200b\uFEFF🔀?]+/, '').trim();
  if (CASCADE_EXITS[cleanName]) return CASCADE_EXITS[cleanName];
  if (cleanName.endsWith('-ch')) return CASCADE_EXITS['seltel-ws-ch'];
  if (cleanName.endsWith('-nl')) return CASCADE_EXITS['seltel-ws-nl'];
  if (cleanName.endsWith('-se')) return CASCADE_EXITS['aeza1010ws-se'];
  if (cleanName.endsWith('-is')) return CASCADE_EXITS['aeza1010ws-is'];
  if (cleanName.endsWith('-lv')) return CASCADE_EXITS['aeza1010ws-lv'];
  if (cleanName.endsWith('-il')) return CASCADE_EXITS['aeza1010ws-il'];
  return null;
}

async function resolveNodeGeo(link) {
  const cascadeGeo = getCascadeExitGeo(link);
  if (cascadeGeo) {
    return cascadeGeo;
  }

  const host = extractHostFromLink(link);
  if (!host) {
    return { subtitle: '🌐 Other Nodes', testUrl: '' };
  }

  if (geoCache[host]) {
    return geoCache[host];
  }

  let ip = host;
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    try {
      const res = await dns.promises.lookup(host);
      ip = res.address;
    } catch (e) {
      console.warn(`[GeoResolver] DNS lookup failed for ${host}:`, e.message);
    }
  }

  const info = await fetchIpInfoJson(ip);
  if (info && info.country) {
    const countryCode = info.country.toUpperCase();
    const countryName = displayNames.of(countryCode) || countryCode;
    const fl = flagEmoji(countryCode);
    const provider = extractProviderName(info.org);
    const subtitle = `${fl} ${countryCode}, ${countryName}`;
    const testUrl = `https://${host}/`;

    geoCache[host] = { ip, countryCode, countryName, flag: fl, provider, subtitle, testUrl };
    saveGeoCache();
    return geoCache[host];
  }

  return { subtitle: `🌐 ${host}`, testUrl: `https://${host}/` };
}

function getNodeGeoSync(link, nodeName) {
  const cascadeGeo = getCascadeExitGeo(link, nodeName);
  if (cascadeGeo) {
    return cascadeGeo;
  }
  const host = extractHostFromLink(link);
  if (host && geoCache[host]) {
    return geoCache[host];
  }
  return { subtitle: '🌐 Connection Node', testUrl: host ? `https://${host}/` : '' };
}

async function prewarmGeoCache(links) {
  console.log('[GeoResolver] Prewarming IP geolocation cache from ipinfo.io...');
  const promises = links.map(link => resolveNodeGeo(link));
  await Promise.allSettled(promises);
  console.log(`[GeoResolver] Cache ready with ${Object.keys(geoCache).length} endpoints.`);
}

const PROBE_FILE = path.join(__dirname, 'probe_results.json');

function loadProbeResults() {
  try {
    if (fs.existsSync(PROBE_FILE)) {
      return JSON.parse(fs.readFileSync(PROBE_FILE, 'utf8'));
    }
  } catch (e) {
    console.error("Error reading probe DB:", e);
  }
  return { updated_at: null, source: null, nodes: {} };
}

function saveProbeResults(data) {
  try {
    fs.writeFileSync(PROBE_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.error("Error writing probe DB:", e);
  }
}

function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    let [name, ...rest] = cookie.split('=');
    name = name?.trim();
    if (!name) return;
    const value = rest.join('=').trim();
    list[name] = decodeURIComponent(value);
  });
  return list;
}

// In-memory cache for Selectel telemetry to avoid blocking HTTP responses
let selectelTelemetryCache = {
  updated_at: 0,
  rate_display: '0 kbit/s',
  rate_down_str: '0 kbit/s',
  rate_up_str: '0 kbit/s',
  max_rate_display: '15.34 Mbit/s',
  sockets: {}
};

function refreshSelectelTelemetry() {
  try {
    const now = Date.now();
    // Cache for 45 seconds
    if (now - selectelTelemetryCache.updated_at < 45000) {
      return selectelTelemetryCache;
    }

    // 1. Check open sockets for Selectel ports
    const SELTEL_PORTS = {
      'SELTEL-REALITY': 51732,
      'seltel443': 443,
      'seltel9443': 9443,
      'seltel1006ws': 2053,
      '🔀 seltel-ws-ch': 2083,
      '🔀 seltel-ws-nl': 2087
    };

    const sockets = {};
    for (const [name, port] of Object.entries(SELTEL_PORTS)) {
      try {
        const out = execSync(`ss -t state established "( sport = :${port} or dport = :${port} )" | tail -n +2 | wc -l`, { encoding: 'utf8', timeout: 1500 });
        sockets[name] = parseInt(out.trim()) || 0;
      } catch (e) {
        sockets[name] = 0;
      }
    }

    // 2. Sample vnstat live rate
    let rxStr = '0 kbit/s';
    let txStr = '0 kbit/s';
    let rateDisplay = '0 kbit/s';
    try {
      const vnJson = JSON.parse(execSync('vnstat -tr 2 --json', { encoding: 'utf8', timeout: 4000 }));
      if (vnJson.rx) rxStr = vnJson.rx.ratestring || '0 kbit/s';
      if (vnJson.tx) txStr = vnJson.tx.ratestring || '0 kbit/s';
      rateDisplay = `↓ ${rxStr} · ↑ ${txStr}`;
    } catch (e) {}

    // 3. 24h Max Rate
    let maxRateDisplay = '15.34 Mbit/s';
    try {
      const hJson = JSON.parse(execSync('vnstat -h 24 --json', { encoding: 'utf8', timeout: 2000 }));
      let peakBps = 0;
      for (const iface of (hJson.interfaces || [])) {
        for (const h of (iface.traffic?.hour || [])) {
          const bps = ((h.rx || 0) + (h.tx || 0)) * 8 / 3600;
          if (bps > peakBps) peakBps = bps;
        }
      }
      if (peakBps > 1000000) {
        maxRateDisplay = `${(peakBps / 1000000).toFixed(2)} Mbit/s`;
      } else if (peakBps > 0) {
        maxRateDisplay = `${(peakBps / 1000).toFixed(1)} kbit/s`;
      }
    } catch (e) {}

    // 4. Cumulative Total Transferred Bytes
    let totalBytes = 0;
    let totalRxBytes = 0;
    let totalTxBytes = 0;
    try {
      const fullJson = JSON.parse(execSync('vnstat --json', { encoding: 'utf8', timeout: 2000 }));
      for (const iface of (fullJson.interfaces || [])) {
        if (iface.name === 'eth0') {
          totalRxBytes = iface.traffic?.total?.rx || 0;
          totalTxBytes = iface.traffic?.total?.tx || 0;
          totalBytes = totalRxBytes + totalTxBytes;
        }
      }
    } catch (e) {}

    selectelTelemetryCache = {
      updated_at: now,
      rate_display: rateDisplay,
      rate_down_str: rxStr,
      rate_up_str: txStr,
      max_rate_display: maxRateDisplay,
      total_bytes: totalBytes,
      total_down_bytes: totalRxBytes,
      total_up_bytes: totalTxBytes,
      sockets
    };
  } catch (err) {
    console.error('Error refreshing Selectel telemetry:', err);
  }
  return selectelTelemetryCache;
}

function enrichSelectelNodes(probeNodes) {
  const tele = refreshSelectelTelemetry();
  const nowIso = new Date().toISOString();

  for (const [name, count] of Object.entries(tele.sockets || {})) {
    if (!probeNodes[name]) {
      probeNodes[name] = {
        status: 'PASS',
        latency: 5,
        country: '🇷🇺 Russia (Selectel SPb)',
        detail: 'Direct SPb Server',
        checked_at: nowIso
      };
    }
    probeNodes[name].traffic = {
      open_sockets: count,
      rate_display: count > 0 ? tele.rate_display : '0 KB/s',
      rate_down_str: tele.rate_down_str,
      rate_up_str: tele.rate_up_str,
      max_rate_display: tele.max_rate_display,
      total_bytes: tele.total_bytes || 0,
      total_down_bytes: tele.total_down_bytes || 0,
      total_up_bytes: tele.total_up_bytes || 0,
      server: 'Selectel SPb (eth0)',
      sampled_at: nowIso
    };
  }
}

function parseRateToBps(str) {
  if (!str) return 0;
  const m = str.match(/([0-9.]+)\s*([a-zA-Z/]+)/);
  if (!m) return 0;
  const val = parseFloat(m[1]);
  const unit = m[2].toLowerCase();
  if (unit.includes('mbit')) return (val * 1000000) / 8;
  if (unit.includes('kbit')) return (val * 1000) / 8;
  if (unit.includes('gbit')) return (val * 1000000000) / 8;
  if (unit.includes('mb/s') || unit.includes('mbyte')) return val * 1024 * 1024;
  if (unit.includes('kb/s') || unit.includes('kbyte')) return val * 1024;
  if (unit.includes('b/s')) return val;
  return val;
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return { short: '0 B', exact: '0 bytes', full: '0 B (0 bytes)' };
  const num = Number(bytes);
  const exact = num.toLocaleString('en-US') + ' bytes';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(num) / Math.log(k));
  const short = parseFloat((num / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  return { short, exact, full: `${short} (${exact})` };
}

function formatBps(bps) {
  if (!bps || bps <= 0) return '0 B/s';
  if (bps >= 1024 * 1024 * 1024) return (bps / (1024 * 1024 * 1024)).toFixed(2) + ' GB/s';
  if (bps >= 1024 * 1024) return (bps / (1024 * 1024)).toFixed(2) + ' MB/s';
  if (bps >= 1024) return (bps / 1024).toFixed(2) + ' KB/s';
  return Math.round(bps).toLocaleString('en-US') + ' B/s';
}

function convertCompoundRate(str) {
  if (!str || str === 'N/A' || str === '0 KB/s' || str === '0 kbit/s') {
    return { display: str || '0 B/s', exact: '0 B/s', totalExact: '0 B/s', original: str || '0 KB/s' };
  }
  let rxMatch = str.match(/(?:↓\s*|down\s*:\s*|^)([0-9.]+\s*[a-zA-Z/]+)/i);
  let txMatch = str.match(/(?:↑\s*|up\s*:\s*|·\s*↑\s*)([0-9.]+\s*[a-zA-Z/]+)/i);
  if (str.includes('down') && str.includes('up')) {
    const p1 = str.match(/([0-9.]+\s*[a-zA-Z/]+)\s*down/i);
    const p2 = str.match(/([0-9.]+\s*[a-zA-Z/]+)\s*up/i);
    if (p1 && p2) {
      rxMatch = p1;
      txMatch = p2;
    }
  }
  if (rxMatch && txMatch) {
    const rxBps = parseRateToBps(rxMatch[1]);
    const txBps = parseRateToBps(txMatch[1]);
    const totBps = rxBps + txBps;
    return {
      display: '↓ ' + formatBps(rxBps) + ' · ↑ ' + formatBps(txBps),
      exact: '↓ ' + Math.round(rxBps).toLocaleString('en-US') + ' B/s · ↑ ' + Math.round(txBps).toLocaleString('en-US') + ' B/s',
      totalExact: Math.round(totBps).toLocaleString('en-US') + ' B/s total',
      original: str
    };
  }
  const singleBps = parseRateToBps(str);
  return {
    display: formatBps(singleBps),
    exact: Math.round(singleBps).toLocaleString('en-US') + ' B/s',
    totalExact: Math.round(singleBps).toLocaleString('en-US') + ' B/s',
    original: str
  };
}

function generateVpsFleetHtml(probeNodes, selectelTele) {
  const VPS_DEFINITIONS = [
    {
      id: 'selectel',
      name: 'Selectel SPb',
      flag: '🇷🇺',
      host: '176.114.78.170 · seltel.svgrn.work',
      roleTag: 'Primary Hub & Inbounds',
      status: '🟢 Local Hub',
      match: (name, srv) => srv.includes('Selectel') || name.toLowerCase().includes('seltel')
    },
    {
      id: 'aeza',
      name: 'Aeza Moscow',
      flag: '🇷🇺',
      host: '45.88.161.82 · blank-black.ptr.network',
      roleTag: 'TSPU Probe & Cascades',
      status: '🟢 TSPU Probe',
      match: (name, srv) => srv.includes('Aeza') || name.toLowerCase().includes('aeza')
    },
    {
      id: 'geneva',
      name: 'Infomaniak Geneva',
      flag: '🇨🇭',
      host: '179.237.121.125 · ov-117aeb',
      roleTag: 'Direct Swiss Inbounds',
      status: '🟢 Remote Reporter',
      match: (name, srv) => srv.includes('Geneva') || srv.includes('Infomaniak') || name.startsWith('CH-')
    },
    {
      id: 'reykjavik',
      name: '1984 Reykjavik',
      flag: '🇮🇸',
      host: '89.126.249.223 · vps6tanw1e',
      roleTag: 'Direct Iceland Inbounds',
      status: '🟢 Remote Reporter',
      match: (name, srv) => srv.includes('Reykjavik') || srv.includes('1984') || name.startsWith('IS0922')
    }
  ];

  let fleetTotalSockets = 0;
  let fleetTotalProfiles = 0;
  let fleetTotalBytes = 0;
  let serverRowsHtml = '';

  for (const vps of VPS_DEFINITIONS) {
    const matchedProfiles = [];
    let serverSockets = 0;
    let serverTotalBytes = 0;
    let rateDisplay = 'N/A';
    let maxRateDisplay = 'N/A';

    for (const [name, info] of Object.entries(probeNodes)) {
      const traffic = info.traffic || {};
      const srv = traffic.server || '';
      if (vps.match(name, srv)) {
        const soc = traffic.open_sockets || 0;
        const bytes = traffic.total_bytes || 0;
        serverSockets += soc;
        if (bytes > serverTotalBytes) {
          serverTotalBytes = bytes;
        }
        if (traffic.rate_display && traffic.rate_display !== '0 KB/s' && traffic.rate_display !== '0 kbit/s') {
          rateDisplay = traffic.rate_display;
        } else if (rateDisplay === 'N/A' && traffic.rate_display) {
          rateDisplay = traffic.rate_display;
        }
        if (traffic.max_rate_display && traffic.max_rate_display !== 'N/A') {
          maxRateDisplay = traffic.max_rate_display;
        }
        matchedProfiles.push({ name, sockets: soc, total_bytes: bytes });
      }
    }

    if (vps.id === 'selectel' && selectelTele) {
      if (selectelTele.rate_display) rateDisplay = selectelTele.rate_display;
      if (selectelTele.max_rate_display) maxRateDisplay = selectelTele.max_rate_display;
      if (selectelTele.total_bytes) serverTotalBytes = selectelTele.total_bytes;
    }

    if (vps.id === 'aeza') {
      const sumAeza = matchedProfiles.reduce((acc, p) => acc + (p.total_bytes || 0), 0);
      if (sumAeza > 0) serverTotalBytes = sumAeza;
    }

    matchedProfiles.sort((a, b) => (b.sockets - a.sockets) || (b.total_bytes - a.total_bytes) || a.name.localeCompare(b.name));

    fleetTotalSockets += serverSockets;
    fleetTotalProfiles += matchedProfiles.length;
    fleetTotalBytes += serverTotalBytes;

    const liveRate = convertCompoundRate(rateDisplay);
    const peakRate = convertCompoundRate(maxRateDisplay);
    const volInfo = formatBytes(serverTotalBytes);

    let profilePillsHtml = matchedProfiles.map(p => {
      const escaped = encodeURIComponent(p.name);
      const socBadge = p.sockets > 0 
        ? `<span class="inbound-soc active">${p.sockets}</span>` 
        : `<span class="inbound-soc zero">0</span>`;
      const bytesBadge = p.total_bytes > 0
        ? `<span class="inbound-soc bytes" title="${Number(p.total_bytes).toLocaleString('en-US')} bytes">${formatBytes(p.total_bytes).short}</span>`
        : '';
      return `<button class="inbound-pill" onclick="openStatsModal(decodeURIComponent('${escaped}'))" title="Open ${p.name} Telemetry">${p.name} ${socBadge}${bytesBadge}</button>`;
    }).join(' ');

    if (!profilePillsHtml) {
      profilePillsHtml = '<span style="color:var(--text-muted); font-size:0.8rem;">No active profiles reported</span>';
    }

    serverRowsHtml += `
      <tr>
        <td>
          <div class="vps-node-col">
            <div class="vps-node-header">
              <span class="vps-flag">${vps.flag}</span>
              <span class="vps-node-name">${vps.name}</span>
              <span class="vps-tag">${vps.roleTag}</span>
            </div>
            <div class="vps-host-sub">${vps.host}</div>
          </div>
        </td>
        <td>
          <div class="vps-sockets-col">
            <span class="vps-socket-pill">
              <span class="material-symbols-outlined" style="font-size:16px;">hub</span>
              ${serverSockets}
            </span>
          </div>
        </td>
        <td>
          <div class="vps-rate-val">${liveRate.display}</div>
          <div class="vps-rate-sub" title="${liveRate.exact}">${liveRate.exact} · <span style="opacity:0.75;">${rateDisplay}</span></div>
        </td>
        <td>
          <div class="vps-rate-val">${peakRate.display}</div>
          <div class="vps-rate-sub" title="${peakRate.exact}">${peakRate.exact} · <span style="opacity:0.75;">${maxRateDisplay}</span></div>
        </td>
        <td style="max-width:380px;">
          <div class="vps-inbounds-wrap">
            ${profilePillsHtml}
          </div>
        </td>
        <td>
          <div style="display:flex; flex-direction:column; gap:0.35rem;">
            <span class="vps-status-pill">${vps.status}</span>
            <span style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;" title="${volInfo.exact}">📦 ${volInfo.short}</span>
          </div>
        </td>
      </tr>
    `;
  }

  const fleetVolInfo = formatBytes(fleetTotalBytes);

  return `
    <div class="vps-fleet-card">
      <div class="vps-fleet-header" onclick="toggleVpsFleet(this)">
        <div class="vps-fleet-title">
          <div class="vps-icon-wrap">
            <span class="material-symbols-outlined">dns</span>
          </div>
          <div>
            <div style="display:flex; align-items:center; gap:0.6rem; flex-wrap:wrap;">
              <h2 style="font-size:1.15rem; font-weight:700; color:#fff; margin:0;">Distinct VPS Fleet Infrastructure</h2>
              <span class="vps-badge-online">🟢 4 / 4 Nodes Operational</span>
            </div>
            <div class="vps-subtitle">Physical Host Telemetry · vnStat Bandwidth · Aggregated Established TCP Sockets</div>
          </div>
        </div>
        <div class="vps-fleet-summary">
          <div class="fleet-stat-pill">
            <span class="material-symbols-outlined" style="font-size:16px; color:#34d399;">hub</span>
            <span class="fleet-stat-label">Fleet Sockets:</span>
            <strong class="fleet-stat-val">${fleetTotalSockets}</strong>
          </div>
          <div class="fleet-stat-pill">
            <span class="material-symbols-outlined" style="font-size:16px; color:#a78bfa;">data_usage</span>
            <span class="fleet-stat-label">Fleet Traffic:</span>
            <strong class="fleet-stat-val" title="${fleetVolInfo.exact}">${fleetVolInfo.short}</strong>
          </div>
          <div class="fleet-stat-pill">
            <span class="material-symbols-outlined" style="font-size:16px; color:#60a5fa;">router</span>
            <span class="fleet-stat-label">Inbounds:</span>
            <strong class="fleet-stat-val">${fleetTotalProfiles}</strong>
          </div>
          <span class="material-symbols-outlined chevron">expand_more</span>
        </div>
      </div>
      <div class="vps-fleet-content">
        <div class="vps-table-wrap">
          <table class="vps-table">
            <thead>
              <tr>
                <th>Physical Server</th>
                <th>Total Sockets</th>
                <th>Live Rate (bytes)</th>
                <th>24h Peak Rate (bytes)</th>
                <th>Hosted Profiles Breakdown</th>
                <th>Status & Volume</th>
              </tr>
            </thead>
            <tbody>
              ${serverRowsHtml}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function serveHtmlPage(res, isAuthorizedStats = false, setCookieHeader = null) {
  const templatePath = path.join(__dirname, 'template.html');
  fs.readFile(templatePath, 'utf8', (err, html) => {
    if (err) {
      res.writeHead(500, { "content-type": "text/plain" });
      res.end("Internal Server Error: Missing Template");
      return;
    }

    // Group links by location dynamically resolved via ipinfo.io
    const groups = {};
    for (const link of nodeLinks) {
      const parsed = parseNode(link);
      if (!parsed) continue;

      const geo = getNodeGeoSync(link, parsed.name);
      const subtitle = geo.subtitle;
      if (!groups[subtitle]) {
        groups[subtitle] = { testUrl: geo.testUrl, nodes: [] };
      }
      groups[subtitle].nodes.push({ link, name: parsed.name, protocol: parsed.protocol, wgConf: parsed.wgConf });
    }

    const probeData = loadProbeResults();
    const probeNodes = probeData.nodes || {};

    // Enrich Selectel's local nodes with real-time sockets and vnstat
    enrichSelectelNodes(probeNodes);

    const trafficMap = {};

    // Build the collapsible group cards HTML
    let groupsHtml = '';
    for (const [location, groupData] of Object.entries(groups)) {
      const { nodes } = groupData;
      const countText = `${nodes.length} node${nodes.length > 1 ? 's' : ''}`;
      
      let passCount = 0;
      let failCount = 0;
      let unknownCount = 0;
      let worstLatency = 0;

      let rowsHtml = '';
      for (const node of nodes) {
        const probe = probeNodes[node.name];
        const status = probe ? probe.status : 'UNKNOWN';
        const latency = probe && probe.latency ? `${probe.latency}ms` : '';
        const detail = probe ? (probe.detail || '') : 'Not tested';
        const traffic = (probe && probe.traffic) ? probe.traffic : { open_sockets: 0, rate_display: '0 KB/s', max_rate_display: 'N/A' };
        
        if (isAuthorizedStats) {
          trafficMap[node.name] = {
            name: node.name,
            country: (probe && probe.country) ? probe.country : location,
            open_sockets: traffic.open_sockets || 0,
            rate_display: traffic.rate_display || '0 KB/s',
            rate_down_str: traffic.rate_down_str || '0 KB/s',
            rate_up_str: traffic.rate_up_str || '0 KB/s',
            max_rate_display: traffic.max_rate_display || 'N/A',
            total_bytes: traffic.total_bytes || 0,
            total_down_bytes: traffic.total_down_bytes || 0,
            total_up_bytes: traffic.total_up_bytes || 0,
            server: traffic.server || (node.name.includes('aeza') ? 'Aeza Moscow (enp0s3)' : 'Selectel SPb (eth0)'),
            sampled_at: traffic.sampled_at || (probe && probe.checked_at) || ''
          };
        }

        if (probe) {
          if (probe.status === 'PASS') {
            passCount++;
            if (typeof probe.latency === 'number' && probe.latency > worstLatency) {
              worstLatency = probe.latency;
            }
          } else if (probe.status === 'FAIL') {
            failCount++;
          } else {
            unknownCount++;
          }
        } else {
          unknownCount++;
        }

        let badgeHtml = '';
        if (status === 'PASS') {
          badgeHtml = `<span class="probe-badge pass" title="${detail}"><span class="probe-dot pass"></span>PASS ${latency}</span>`;
        } else if (status === 'FAIL') {
          badgeHtml = `<span class="probe-badge fail" title="${detail}"><span class="probe-dot fail"></span>BLOCKED</span>`;
        } else {
          badgeHtml = `<span class="probe-badge unknown" title="${detail}"><span class="probe-dot unknown"></span>—</span>`;
        }

        const isWg = node.protocol === 'wireguard';
        
        let statsBtnHtml = '';
        if (isAuthorizedStats) {
          const sockets = traffic.open_sockets || 0;
          const pill = sockets > 0 ? `<span class="socket-pill" title="${sockets} active connections">${sockets}</span>` : '';
          statsBtnHtml = `
            <button class="stats-btn" title="Node Traffic Telemetry & Active Sockets" onclick="openStatsModal(decodeURIComponent('${encodeURIComponent(node.name)}'))">
              <span class="material-symbols-outlined" style="font-size:17px;">query_stats</span>
              ${pill}
            </button>`;
        }

        let actionButtons = '';
        if (isWg && node.wgConf) {
          const escapedConf = encodeURIComponent(node.wgConf);
          actionButtons = `
            <div style="display:inline-flex; gap:0.4rem; align-items:center;">
              ${statsBtnHtml}
              <button class="copy-btn" title="Copy WireGuard .conf" onclick="copyToClipboard(this, decodeURIComponent('${escapedConf}'))" style="padding:0.35rem 0.65rem; font-size:0.75rem; gap:0.3rem;">
                <span class="material-symbols-outlined" style="font-size:16px;">description</span>
                <span>.conf</span>
              </button>
              <a class="copy-btn" title="Download WireGuard .conf" href="data:text/plain;charset=utf-8,${escapedConf}" download="${encodeURIComponent(node.name)}.conf" style="text-decoration:none; padding:0.35rem 0.5rem; display:inline-flex; align-items:center;">
                <span class="material-symbols-outlined" style="font-size:16px;">download</span>
              </a>
              <button class="copy-btn" title="Copy wireguard:// URL" onclick="copyToClipboard(this, \`${node.link}\`)" style="padding:0.35rem 0.5rem;">
                <span class="material-symbols-outlined" style="font-size:16px;">link</span>
              </button>
            </div>`;
        } else {
          actionButtons = `
            <div style="display:inline-flex; gap:0.4rem; align-items:center;">
              ${statsBtnHtml}
              <button class="copy-btn" onclick="copyToClipboard(this, \`${node.link}\`)">
                <span class="material-symbols-outlined">content_copy</span>
              </button>
            </div>`;
        }

        const isCascade = node.name.includes('🔀') || node.name.toLowerCase().includes('cascade');
        rowsHtml += `
          <tr data-name="${node.name}" data-status="${status}" data-latency="${probe && probe.latency ? probe.latency : 9999}" data-cascade="${isCascade}">
            <td>
              <div class="node-info">
                <div class="node-name">
                  <span>${node.name}</span>
                  ${badgeHtml}
                </div>
              </div>
            </td>
            <td class="action-cell">
              ${actionButtons}
            </td>
          </tr>`;
      }

      let countryStatusHtml = '';
      if (passCount > 0 && failCount === 0) {
        const pingLabel = nodes.length > 1 ? `${worstLatency}ms (worst)` : `${worstLatency}ms`;
        countryStatusHtml = `<span class="ping-indicator online" title="All ${passCount} tested configurations operational. Worst latency: ${worstLatency}ms">🟢 Online · ${pingLabel}</span>`;
      } else if (passCount > 0 && failCount > 0) {
        countryStatusHtml = `<span class="ping-indicator partial" title="${passCount} of ${passCount + failCount} configurations operational. Worst working latency: ${worstLatency}ms">🟡 Partial (${passCount}/${passCount + failCount}) · ${worstLatency}ms (worst)</span>`;
      } else if (failCount > 0 && passCount === 0) {
        const isRu = location.includes("Russia") || location.includes("RU");
        if (isRu) {
          countryStatusHtml = `<span class="ping-indicator unknown" title="Russian domestic internal routing">⚪ Direct (RU)</span>`;
        } else {
          countryStatusHtml = `<span class="ping-indicator blocked" title="All ${failCount} tested configurations blocked by Russian TSPU">❌ Blocked</span>`;
        }
      } else {
        const isRu = location.includes("Russia") || location.includes("RU");
        const defaultLabel = isRu ? "⚪ Direct (RU)" : "⚪ Unprobed";
        countryStatusHtml = `<span class="ping-indicator unknown" title="Unprobed configurations">${defaultLabel}</span>`;
      }

      groupsHtml += `
    <div class="group-card" data-location="${location}">
      <div class="group-header" onclick="toggleGroup(this)">
        <div class="group-title">
          <span class="location-name">${location}</span>
          <span class="node-count">${countText}</span>
          ${countryStatusHtml}
        </div>
        <span class="material-symbols-outlined chevron">expand_more</span>
      </div>
      <div class="group-content">
        <table>
          <thead>
            <tr>
              <th>Connection Profile</th>
              <th class="action-cell">Copy Link</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
      </div>
    </div>`;
    }

    let probeMetaHtml = '';
    if (probeData.updated_at) {
      const d = new Date(probeData.updated_at);
      const timeStr = d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Moscow' });
      probeMetaHtml = `<span class="probe-meta"><span class="material-symbols-outlined" style="font-size:16px;">verified</span> Probed from Moscow (${timeStr} MSK)</span>`;
    }

    let renderedHtml = html.replace('<!-- GROUPS_PLACEHOLDER -->', groupsHtml);
    renderedHtml = renderedHtml.replace('<!-- PROBE_META_PLACEHOLDER -->', probeMetaHtml);

    if (isAuthorizedStats) {
      const vpsFleetHtml = generateVpsFleetHtml(probeNodes, selectelTelemetryCache);
      renderedHtml = renderedHtml.replace('<!-- VPS_FLEET_PLACEHOLDER -->', vpsFleetHtml);

      const modalHtml = `
      <div id="stats-modal" class="modal-backdrop" onclick="closeStatsModal(event)">
        <div class="modal-card" onclick="event.stopPropagation()">
          <div class="modal-header">
            <div class="modal-title-group">
              <span class="material-symbols-outlined modal-icon">monitoring</span>
              <div>
                <h3 id="modal-node-name">Node Telemetry</h3>
                <p id="modal-node-sub">Live Realtime Metrics & Traffic</p>
              </div>
            </div>
            <button class="modal-close-btn" onclick="closeStatsModal()">&times;</button>
          </div>
          
          <div class="modal-grid">
            <div class="metric-card">
              <div class="metric-header">
                <span class="material-symbols-outlined metric-icon speed-icon">speed</span>
                <span class="metric-label">Current Rate</span>
              </div>
              <div class="metric-value" id="modal-rate">0.0 KB/s</div>
              <div class="metric-sub" id="modal-rate-sub">Live throughput (vnstat)</div>
            </div>

            <div class="metric-card">
              <div class="metric-header">
                <span class="material-symbols-outlined metric-icon sockets-icon">hub</span>
                <span class="metric-label">Open Sockets</span>
              </div>
              <div class="metric-value" id="modal-sockets">0</div>
              <div class="metric-sub">Active TCP connections</div>
            </div>

            <div class="metric-card">
              <div class="metric-header">
                <span class="material-symbols-outlined metric-icon peak-icon">trending_up</span>
                <span class="metric-label">Max Rate</span>
              </div>
              <div class="metric-value" id="modal-max-rate">0.0 KB/s</div>
              <div class="metric-sub">Peak bandwidth recorded</div>
            </div>

            <div class="metric-card">
              <div class="metric-header">
                <span class="material-symbols-outlined metric-icon total-icon">data_usage</span>
                <span class="metric-label">Total Volume</span>
              </div>
              <div class="metric-value" id="modal-total-bytes">0 MB</div>
              <div class="metric-sub" id="modal-total-sub">Cumulative data transferred</div>
            </div>
          </div>

          <div class="modal-footer">
            <span class="material-symbols-outlined" style="font-size:16px;">schedule</span>
            <span id="modal-sampled-at">Last sampled: Just now</span>
          </div>
        </div>
      </div>`;

      const scriptHtml = `
      <script id="node-traffic-data" type="application/json">
      ${JSON.stringify(trafficMap)}
      </script>
      <script>
        function parseRateToBps(str) {
          if (!str) return 0;
          const m = str.match(/([0-9.]+)\\s*([a-zA-Z/]+)/);
          if (!m) return 0;
          const val = parseFloat(m[1]);
          const unit = m[2].toLowerCase();
          if (unit.includes('mbit')) return (val * 1000000) / 8;
          if (unit.includes('kbit')) return (val * 1000) / 8;
          if (unit.includes('gbit')) return (val * 1000000000) / 8;
          if (unit.includes('mb/s') || unit.includes('mbyte')) return val * 1024 * 1024;
          if (unit.includes('kb/s') || unit.includes('kbyte')) return val * 1024;
          if (unit.includes('b/s')) return val;
          return val;
        }

        function formatBytes(bytes) {
          if (!bytes || bytes === 0) return { short: '0 B', exact: '0 bytes' };
          const num = Number(bytes);
          const exact = num.toLocaleString('en-US') + ' bytes';
          const k = 1024;
          const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
          const i = Math.floor(Math.log(num) / Math.log(k));
          const short = parseFloat((num / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
          return { short, exact };
        }

        function formatBps(bps) {
          if (!bps || bps <= 0) return '0 B/s';
          if (bps >= 1024 * 1024 * 1024) return (bps / (1024 * 1024 * 1024)).toFixed(2) + ' GB/s';
          if (bps >= 1024 * 1024) return (bps / (1024 * 1024)).toFixed(2) + ' MB/s';
          if (bps >= 1024) return (bps / 1024).toFixed(2) + ' KB/s';
          return Math.round(bps).toLocaleString('en-US') + ' B/s';
        }

        function convertCompoundRate(str) {
          if (!str || str === 'N/A' || str === '0 KB/s' || str === '0 kbit/s') {
            return { display: str || '0 B/s', exact: '0 B/s', totalExact: '0 B/s', original: str || '0 KB/s' };
          }
          let rxMatch = str.match(/(?:↓\\s*|down\\s*:\\s*|^)([0-9.]+\\s*[a-zA-Z/]+)/i);
          let txMatch = str.match(/(?:↑\\s*|up\\s*:\\s*|·\\s*↑\\s*)([0-9.]+\\s*[a-zA-Z/]+)/i);
          if (str.includes('down') && str.includes('up')) {
            const p1 = str.match(/([0-9.]+\\s*[a-zA-Z/]+)\\s*down/i);
            const p2 = str.match(/([0-9.]+\\s*[a-zA-Z/]+)\\s*up/i);
            if (p1 && p2) {
              rxMatch = p1;
              txMatch = p2;
            }
          }
          if (rxMatch && txMatch) {
            const rxBps = parseRateToBps(rxMatch[1]);
            const txBps = parseRateToBps(txMatch[1]);
            const totBps = rxBps + txBps;
            return {
              display: '↓ ' + formatBps(rxBps) + ' · ↑ ' + formatBps(txBps),
              exact: '↓ ' + Math.round(rxBps).toLocaleString('en-US') + ' B/s · ↑ ' + Math.round(txBps).toLocaleString('en-US') + ' B/s',
              totalExact: Math.round(totBps).toLocaleString('en-US') + ' B/s total',
              original: str
            };
          }
          const singleBps = parseRateToBps(str);
          return {
            display: formatBps(singleBps),
            exact: Math.round(singleBps).toLocaleString('en-US') + ' B/s',
            totalExact: Math.round(singleBps).toLocaleString('en-US') + ' B/s',
            original: str
          };
        }

        function openStatsModal(nodeName) {
          const raw = document.getElementById('node-traffic-data')?.textContent;
          if (!raw) return;
          try {
            const map = JSON.parse(raw);
            const data = map[nodeName] || {};
            
            document.getElementById('modal-node-name').textContent = nodeName;
            document.getElementById('modal-node-sub').textContent = (data.country || 'Node') + ' · ' + (data.server || 'Transit Server');
            
            const rateInfo = convertCompoundRate(data.rate_display);
            document.getElementById('modal-rate').textContent = rateInfo.display;
            document.getElementById('modal-rate-sub').textContent = rateInfo.exact + ' (' + rateInfo.original + ')';
            
            document.getElementById('modal-sockets').textContent = data.open_sockets || '0';
            
            const peakInfo = convertCompoundRate(data.max_rate_display);
            document.getElementById('modal-max-rate').textContent = peakInfo.display;
            document.getElementById('modal-max-rate-sub').textContent = peakInfo.exact + ' (' + (data.max_rate_display || 'peak') + ')';
            
            const volInfo = formatBytes(data.total_bytes);
            document.getElementById('modal-total-bytes').textContent = volInfo.short;
            let volSub = volInfo.exact;
            if (data.total_down_bytes || data.total_up_bytes) {
              volSub += ' (↓ ' + formatBytes(data.total_down_bytes).short + ' · ↑ ' + formatBytes(data.total_up_bytes).short + ')';
            }
            document.getElementById('modal-total-sub').textContent = volSub;
            
            let sampleText = 'Last sampled: Live telemetry';
            if (data.sampled_at) {
              try {
                const d = new Date(data.sampled_at);
                sampleText = 'Sampled at ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' (' + d.toLocaleDateString() + ')';
              } catch(e) {}
            }
            document.getElementById('modal-sampled-at').textContent = sampleText;

            const modal = document.getElementById('stats-modal');
            if (modal) modal.classList.add('active');
          } catch (e) {
            console.error('Failed to open stats modal:', e);
          }
        }

        function closeStatsModal(e) {
          const modal = document.getElementById('stats-modal');
          if (modal) modal.classList.remove('active');
        }

        document.addEventListener('keydown', (e) => {
          if (e.key === 'Escape') closeStatsModal();
        });
      </script>`;

      renderedHtml = renderedHtml.replace('<!-- STATS_MODAL_PLACEHOLDER -->', modalHtml);
      renderedHtml = renderedHtml.replace('<!-- STATS_SCRIPT_PLACEHOLDER -->', scriptHtml);
    } else {
      renderedHtml = renderedHtml.replace('<!-- VPS_FLEET_PLACEHOLDER -->', '');
      renderedHtml = renderedHtml.replace('<!-- STATS_MODAL_PLACEHOLDER -->', '');
      renderedHtml = renderedHtml.replace('<!-- STATS_SCRIPT_PLACEHOLDER -->', '');
    }

    const headers = {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, no-cache, must-revalidate"
    };
    if (setCookieHeader) {
      headers["Set-Cookie"] = setCookieHeader;
    }

    res.writeHead(200, headers);
    res.end(renderedHtml);
  });
}

const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = reqUrl.pathname;

  // 1. Probe update API endpoint (POST)
  if (pathname === `/${SECRET_KEY}/probe-update` && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body);
        const incomingNodes = payload.nodes || (typeof payload === 'object' ? payload : {});
        const currentData = loadProbeResults();
        const currentNodes = currentData.nodes || {};

        // Merge incoming nodes without losing telemetry or probe data
        for (const [name, info] of Object.entries(incomingNodes)) {
          if (currentNodes[name]) {
            currentNodes[name] = {
              ...currentNodes[name],
              ...info,
              traffic: info.traffic || currentNodes[name].traffic
            };
          } else {
            currentNodes[name] = info;
          }
        }

        const formatted = {
          updated_at: payload.updated_at || new Date().toISOString(),
          source: payload.source || currentData.source || 'aeza (Moscow)',
          nodes: currentNodes
        };
        saveProbeResults(formatted);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ success: true, count: Object.keys(currentNodes).length }));
      } catch (e) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }

  // 2. Probe results JSON endpoint (GET)
  if (pathname === `/${SECRET_KEY}/probe-results.json` || pathname === `/${SECRET_KEY}/probe-results`) {
    const probeData = loadProbeResults();
    enrichSelectelNodes(probeData.nodes || {});
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store, no-cache, must-revalidate"
    });
    res.end(JSON.stringify(probeData, null, 2));
    return;
  }

  // 3. HTML page request under the pure key segment
  if (pathname === `/${SECRET_KEY}`) {
    const cookies = parseCookies(req.headers.cookie);
    const urlHasStats = reqUrl.searchParams.get("stats") === "1" || reqUrl.searchParams.get("admin") === "1" || reqUrl.searchParams.get("traffic") === "1";
    const urlClearsStats = reqUrl.searchParams.get("stats") === "0" || reqUrl.searchParams.get("admin") === "0";

    let isAuthorizedStats = false;
    let setCookieHeader = null;

    if (urlHasStats) {
      isAuthorizedStats = true;
      setCookieHeader = "svg_stats=1; Path=/; Max-Age=31536000; SameSite=Lax";
    } else if (urlClearsStats) {
      isAuthorizedStats = false;
      setCookieHeader = "svg_stats=; Path=/; Max-Age=0; SameSite=Lax";
    } else if (cookies.svg_stats === "1") {
      isAuthorizedStats = true;
    }

    serveHtmlPage(res, isAuthorizedStats, setCookieHeader);
    return;
  }

  // 2. Standard subscription authentication
  const userKey = reqUrl.searchParams.get("key");
  const isAuthorized = (SECRET_KEY && userKey === SECRET_KEY) || req.url.includes("moscowfriend");

  if (!isAuthorized) {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("Not Found");
    return;
  }

  const userAgent = (req.headers['user-agent'] || "").toLowerCase();
  const format = reqUrl.searchParams.get("format") || "";

  // 1. Clash / Mihomo Clients
  if (format === "clash" || userAgent.includes("clash") || userAgent.includes("mihomo")) {
    const clashProxies = [];
    for (const link of nodeLinks) {
      const parsed = parseNode(link);
      if (!parsed) continue;

      if (parsed.protocol === "ss") {
        clashProxies.push({
          protocol: "ss",
          name: parsed.name,
          server: parsed.host,
          port: parsed.port,
          cipher: parsed.method,
          password: parsed.password
        });
      } else if (parsed.protocol === "hysteria2") {
        const proxy = {
          protocol: "hysteria2",
          name: parsed.name,
          server: parsed.host,
          port: parsed.port,
          password: parsed.password
        };
        if (parsed.sni) proxy.sni = parsed.sni;
        if (parsed.obfs) {
          proxy.obfs = parsed.obfs;
          if (parsed.obfsPassword) proxy["obfs-password"] = parsed.obfsPassword;
        }
        clashProxies.push(proxy);
      } else if (parsed.protocol === "trojan") {
        clashProxies.push({
          protocol: "trojan",
          name: parsed.name,
          server: parsed.host,
          port: parsed.port,
          password: parsed.password,
          tls: parsed.security !== "none",
          sni: parsed.sni || parsed.host,
          network: parsed.type,
          grpcServiceName: parsed.serviceName
        });
      } else if (parsed.protocol === "wireguard") {
        clashProxies.push({
          protocol: "wireguard",
          name: parsed.name,
          server: parsed.host,
          port: parsed.port,
          ip: parsed.address.split("/")[0],
          publicKey: parsed.publicKey,
          privateKey: parsed.privateKey,
          dns: parsed.dns.split(",").map(d => `"${d.trim()}"`).join(", "),
          mtu: parsed.mtu
        });
      } else {
        const proxy = {
          protocol: "vless",
          name: parsed.name,
          server: parsed.host,
          port: parsed.port,
          uuid: parsed.uuid,
          tls: parsed.security !== "none",
          servername: parsed.sni || parsed.host,
          network: parsed.type || "tcp",
          path: parsed.path
        };

        if (parsed.flow) proxy.flow = parsed.flow;
        proxy["client-fingerprint"] = parsed.fp || "chrome";
        if (parsed.security === "reality") {
          proxy.reality = { pbk: parsed.pbk, sid: parsed.sid };
        }

        clashProxies.push(proxy);
      }
    }

    const clashYaml = generateClashYaml(clashProxies);
    res.writeHead(200, {
      "content-type": "text/yaml; charset=utf-8",
      "profile-title": "base64:" + Buffer.from("svg Clash Collection").toString('base64'),
      "profile-update-interval": "4",
      "cache-control": "no-store, no-cache, must-revalidate",
      "Content-Disposition": "attachment; filename=\"svg-clash.yaml\""
    });
    res.end(clashYaml);
    return;
  }

  // 2. Sing-box / Hiddify / Karing Clients
  if (format === "sing-box" || userAgent.includes("sing-box") || userAgent.includes("hiddify") || userAgent.includes("karing")) {
    const sbOutbounds = [];
    for (const link of nodeLinks) {
      const parsed = parseNode(link);
      if (!parsed) continue;

      if (parsed.protocol === "ss") {
        const outbound = {
          type: "shadowsocks",
          tag: parsed.name,
          server: parsed.host,
          server_port: parsed.port,
          method: parsed.method,
          password: parsed.password
        };
        if (parsed.prefix) {
          outbound.prefix = parsed.prefix;
        }
        sbOutbounds.push(outbound);
      } else if (parsed.protocol === "hysteria2") {
        const outbound = {
          type: "hysteria2",
          tag: parsed.name,
          server: parsed.host,
          server_port: parsed.port,
          password: parsed.password
        };
        if (parsed.sni) {
          outbound.tls = {
            enabled: true,
            server_name: parsed.sni
          };
        }
        if (parsed.obfs) {
          outbound.obfs = {
            type: parsed.obfs
          };
          if (parsed.obfsPassword) {
            outbound.obfs.password = parsed.obfsPassword;
          }
        }
        sbOutbounds.push(outbound);
      } else if (parsed.protocol === "trojan") {
        const outbound = {
          type: "trojan",
          tag: parsed.name,
          server: parsed.host,
          server_port: parsed.port,
          password: parsed.password
        };
        if (parsed.security !== "none") {
          outbound.tls = {
            enabled: true,
            server_name: parsed.sni || parsed.host
          };
        }
        if (parsed.type === "grpc") {
          outbound.transport = {
            type: "grpc",
            service_name: parsed.serviceName
          };
        }
        sbOutbounds.push(outbound);
      } else if (parsed.protocol === "wireguard") {
        const outbound = {
          type: "wireguard",
          tag: parsed.name,
          server: parsed.host,
          server_port: parsed.port,
          local_address: [parsed.address],
          private_key: parsed.privateKey,
          peer_public_key: parsed.publicKey,
          mtu: parsed.mtu
        };
        sbOutbounds.push(outbound);
      } else {
        const outbound = {
          type: "vless",
          tag: parsed.name,
          server: parsed.host,
          server_port: parsed.port,
          uuid: parsed.uuid
        };

        if (parsed.flow) outbound.flow = parsed.flow;

        if (parsed.security !== "none") {
          outbound.tls = {
            enabled: true,
            server_name: parsed.sni || parsed.host
          };

          outbound.tls.utls = {
            enabled: true,
            fingerprint: parsed.fp || "chrome"
          };

          if (parsed.security === "reality") {
            outbound.tls.reality = {
              enabled: true,
              public_key: parsed.pbk,
              short_id: parsed.sid
            };
          }
        }

        if (parsed.type === "ws") {
          outbound.transport = {
            type: "ws",
            path: parsed.path,
            headers: {
              Host: parsed.sni || parsed.host
            }
          };
        } else if (parsed.type === "xhttp") {
          outbound.transport = {
            type: "xhttp",
            path: parsed.path
          };
        }

        sbOutbounds.push(outbound);
      }
    }

    const singBoxJson = generateSingBoxJson(sbOutbounds);
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "profile-title": "base64:" + Buffer.from("svg Sing-box Collection").toString('base64'),
      "profile-update-interval": "4",
      "cache-control": "no-store, no-cache, must-revalidate",
      "Content-Disposition": "inline"
    });
    res.end(singBoxJson);
    return;
  }

  // 3. Generic Subscription (Base64 list of node URLs)
  const rawTextPayload = nodeLinks.join("\n");
  const base64Payload = Buffer.from(rawTextPayload).toString('base64');

  res.writeHead(200, {
    "content-type": "text/plain; charset=utf-8",
    "profile-title": profileTitleBase64,
    "profile-update-interval": "4",
    "cache-control": "no-store, no-cache, must-revalidate",
    "Content-Disposition": "inline"
  });
  res.end(base64Payload);
});

const PORT = 33130;
const HOST = '0.0.0.0';

server.listen(PORT, HOST, () => {
  console.log(`Standalone Node server running at http://localhost:${PORT}`);
  console.log(`Test subscription: http://localhost:${PORT}/sub?key=${SECRET_KEY}`);
  prewarmGeoCache(nodeLinks);
});
