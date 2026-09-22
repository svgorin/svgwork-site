const http = require('http');
const https = require('https');
const dns = require('dns');
const fs = require('fs');
const path = require('path');

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

async function resolveNodeGeo(link) {
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
    const subtitle = provider ? `${fl} ${countryCode}, ${countryName} (${provider})` : `${fl} ${countryCode}, ${countryName}`;
    const testUrl = `https://${host}/`;

    geoCache[host] = { ip, countryCode, countryName, flag: fl, provider, subtitle, testUrl };
    saveGeoCache();
    return geoCache[host];
  }

  return { subtitle: `🌐 ${host}`, testUrl: `https://${host}/` };
}

function getNodeGeoSync(link) {
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

const DB_FILE = path.join(__dirname, 'feedback.json');

function loadFeedback() {
  try {
    if (fs.existsSync(DB_FILE)) {
      return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    }
  } catch (e) {
    console.error("Error reading feedback DB:", e);
  }
  return {};
}

function saveFeedback(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.error("Error writing feedback DB:", e);
  }
}

function handleVoteRequest(reqUrl, res) {
  const node = reqUrl.searchParams.get("node");
  const type = reqUrl.searchParams.get("type");

  if (!node || (type !== "up" && type !== "down")) {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ success: false, error: "Invalid parameters" }));
    return;
  }

  const feedback = loadFeedback();
  if (!feedback[node]) {
    feedback[node] = { up: 0, down: 0 };
  }

  feedback[node][type] += 1;
  saveFeedback(feedback);

  res.writeHead(200, {
    "content-type": "application/json",
    "cache-control": "no-store, no-cache, must-revalidate"
  });
  res.end(JSON.stringify({
    success: true,
    up: feedback[node].up,
    down: feedback[node].down
  }));
}

function serveHtmlPage(res) {
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

      const geo = getNodeGeoSync(link);
      const subtitle = geo.subtitle;
      if (!groups[subtitle]) {
        groups[subtitle] = { testUrl: geo.testUrl, nodes: [] };
      }
      groups[subtitle].nodes.push({ link, name: parsed.name, protocol: parsed.protocol, wgConf: parsed.wgConf });
    }

    const feedback = loadFeedback();

    // Build the collapsible group cards HTML
    let groupsHtml = '';
    for (const [location, groupData] of Object.entries(groups)) {
      const { testUrl, nodes } = groupData;
      const countText = `${nodes.length} node${nodes.length > 1 ? 's' : ''}`;
      
      let rowsHtml = '';
      for (const node of nodes) {
        const fb = feedback[node.name] || { up: 0, down: 0 };
        const isWg = node.protocol === 'wireguard';
        
        let actionButtons = '';
        if (isWg && node.wgConf) {
          const escapedConf = encodeURIComponent(node.wgConf);
          actionButtons = `
            <div style="display:inline-flex; gap:0.4rem; align-items:center;">
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
            <button class="copy-btn" onclick="copyToClipboard(this, \`${node.link}\`)">
              <span class="material-symbols-outlined">content_copy</span>
            </button>`;
        }

        rowsHtml += `
          <tr data-name="${node.name}" data-score="${fb.up - fb.down}">
            <td>
              <div class="node-info">
                <div class="node-name">
                  ${node.name}
                  <div class="vote-container" data-node="${node.name}">
                    <button class="vote-btn vote-up" onclick="vote('${node.name}', 'up')">
                      <span class="vote-emoji">✅</span>
                      <span class="vote-count" id="count-up-${node.name}">${fb.up}</span>
                    </button>
                    <button class="vote-btn vote-down" onclick="vote('${node.name}', 'down')">
                      <span class="vote-emoji">❌</span>
                      <span class="vote-count" id="count-down-${node.name}">${fb.down}</span>
                    </button>
                  </div>
                </div>
              </div>
            </td>
            <td class="action-cell">
              ${actionButtons}
            </td>
          </tr>`;
      }

      groupsHtml += `
    <div class="group-card" data-test-url="${testUrl}">
      <div class="group-header" onclick="toggleGroup(this)">
        <div class="group-title">
          <span class="location-name">${location}</span>
          <span class="node-count">${countText}</span>
          <span class="ping-indicator" id="ping-${location.replace(/[^a-zA-Z0-9]/g, '')}">[Testing...]</span>
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

    const renderedHtml = html.replace('<!-- GROUPS_PLACEHOLDER -->', groupsHtml);
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, no-cache, must-revalidate"
    });
    res.end(renderedHtml);
  });
}

const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = reqUrl.pathname;

  // 1. Vote API endpoint
  if (pathname === `/${SECRET_KEY}/vote`) {
    handleVoteRequest(reqUrl, res);
    return;
  }

  // 2. HTML page request under the pure key segment
  if (pathname === `/${SECRET_KEY}`) {
    serveHtmlPage(res);
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
        if (parsed.fp) proxy["client-fingerprint"] = parsed.fp;
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

          if (parsed.fp) {
            outbound.tls.utls = {
              enabled: true,
              fingerprint: parsed.fp
            };
          }

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
