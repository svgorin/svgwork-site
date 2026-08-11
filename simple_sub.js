const http = require('http');
const fs = require('fs');
const path = require('path');

const SECRET_KEY = "Im7R9FYpBFwXmKX6";
const profileTitle = "svg Collection";
const profileTitleBase64 = "base64:" + Buffer.from(profileTitle).toString('base64');

const nodeLinks = require('./node_links');

// Helper: Parse VLESS, Shadowsocks (ss://) and Hysteria 2 (hysteria2://) URLs
function parseNode(link) {
  try {
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

function getLocationSubtitle(url, name) {
  const u = url.toLowerCase();
  const n = name.toLowerCase();
  
  if (n.includes("md") || u.includes("md.svgrn.work") || u.includes("md-2.svgrn.work")) {
    return "🇲🇩 MD, Moldova";
  } else if (n.includes("lv") || u.includes("veesp.svgrn.work") || u.includes("veesp-2.svgrn.work")) {
    return "🇱🇻 LV, Latvia";
  } else if (n.includes("il") || u.includes("ilpt2.svgrn.work") || u.includes("saltydyar.click")) {
    return "🇮🇱 IL, Israel";
  } else if (n.includes("seltel") || u.includes("seltel.svgrn.work")) {
    return "🇷🇺 RU, Russia (Selectel)";
  } else if (n.includes("timeweb") || u.includes("timeweb.svgrn.work")) {
    return "🇷🇺 RU, Russia (Timeweb)";
  }
  return "🌐 Connection Node";
}

function serveHtmlPage(res) {
  const templatePath = path.join(__dirname, 'template.html');
  fs.readFile(templatePath, 'utf8', (err, html) => {
    if (err) {
      res.writeHead(500, { "content-type": "text/plain" });
      res.end("Internal Server Error: Missing Template");
      return;
    }

    // Group links by location
    const groups = {};
    for (const link of nodeLinks) {
      const parsed = parseNode(link);
      if (!parsed) continue;

      const subtitle = getLocationSubtitle(link, parsed.name);
      if (!groups[subtitle]) {
        groups[subtitle] = [];
      }
      groups[subtitle].push({ link, name: parsed.name });
    }

    // Build the collapsible group cards HTML
    let groupsHtml = '';
    for (const [location, nodes] of Object.entries(groups)) {
      const countText = `${nodes.length} node${nodes.length > 1 ? 's' : ''}`;
      
      let rowsHtml = '';
      for (const node of nodes) {
        rowsHtml += `
          <tr>
            <td>
              <div class="node-info">
                <div class="node-name">${node.name}</div>
              </div>
            </td>
            <td class="action-cell">
              <button class="copy-btn" onclick="copyToClipboard(this, \`${node.link}\`)">
                <span class="material-symbols-outlined">content_copy</span>
              </button>
            </td>
          </tr>`;
      }

      groupsHtml += `
    <div class="group-card">
      <div class="group-header" onclick="toggleGroup(this)">
        <div class="group-title">
          <span class="location-name">${location}</span>
          <span class="node-count">${countText}</span>
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

  // 1. HTML page request under the pure key segment
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
});
