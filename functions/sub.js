// functions/sub.js

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);

  // 1. Secret Key Guard (Optional but recommended against bots)
  const SECRET_KEY = "Im7R9FYpBFwXmKX6"; // Change this to your secret key
  const userKey = url.searchParams.get("key");

  if (SECRET_KEY && userKey !== SECRET_KEY) {
    return new Response("Not Found", { 
      status: 404,
      headers: { "content-type": "text/plain" }
    });
  }

  // 2. Define your node URLs (one per line)
  const nodeLinks = [
    // ilpt2xhttp-firstx
    "vless://4e1e74bb-df9d-43ac-945e-890497369d7a@ilpt2.svgrn.work:443?type=xhttp&encryption=none&path=%2Fo8tXBUV0Qe&host=&mode=packet-up&security=tls#ilpt2-xhttp",
    // ilpt2 latest iphone/mtsMsk bypass
    "vless://266185b0-844a-4d00-af3a-384660196d6f@ilpt2.svgrn.work:2053?fp=chrome&sni=ilpt2.svgrn.work&type=ws&path=%2FzG8sPvQe&host=ilpt2.svgrn.work&security=tls#ilpt2-04-07-2026",
    // MyREALITYseltel
    "vless://57825bae-1d76-4be6-81ac-944734401557@seltel.svgrn.work:51732?security=reality&encryption=none&pbk=I_xfb96Z2i5Iz_HoSlD5PuxPNOP6AU33Qz5JR22xcyg&headerType=none&fp=chrome&type=tcp&sni=www.yandex.ru&sid=79f3f8d1cba04c49#MyREALITY-seltel",
    "vless://57825bae-1d76-4be6-81ac-944734401557@seltel.svgrn.work:51732?encryption=none&security=reality&sni=www.yandex.ru&fp=chrome&pbk=I_xfb96Z2i5Iz_HoSlD5PuxPNOP6AU33Qz5JR22xcyk&sid=79f3f8d1cba04c49&type=tcp#SELTEL-REALITY",
    // Timeweb
    "vless://78fb87ba-2ae1-4bb2-8ea4-096e623cec96@timeweb.svgrn.work:443?type=xhttp&encryption=none&path=%2FBxuJlQBYBs&host=timeweb.svgrn.work&mode=packet-up&x_padding_bytes=100-1000&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D&security=tls#TimewebMSK",
    // ILPT2-reality (SNI updated to www.microsoft.com to bypass Google throttling)
    "vless://4e1e74bb-df9d-43ac-945e-890497369d7a@185.28.152.61:443?security=reality&encryption=none&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&pbk=Pg9mXzrcCaW6lEYs9IztnM8H5bj_i0OcFIG2QIqNLxs&sni=www.microsoft.com&sid=84e052553543594e#ilpt2-reality"
  ];

  const userAgent = (request.headers.get("User-Agent") || "").toLowerCase();
  const format = url.searchParams.get("format") || "";

  // Helper: Parse VLESS and Shadowsocks (ss://) URLs
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
            const decoded = atob(rawUser);
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
            geosite: ["category-gov-ru"],
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

  // --- Dynamic Route Selection ---

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
    return new Response(clashYaml, {
      status: 200,
      headers: {
        "content-type": "text/yaml; charset=utf-8",
        "profile-title": "base64:" + btoa("svg Clash Collection"),
        "profile-update-interval": "4",
        "cache-control": "no-store, no-cache, must-revalidate",
        "Content-Disposition": "attachment; filename=\"svg-clash.yaml\""
      }
    });
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
    return new Response(singBoxJson, {
      status: 200,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "profile-title": "base64:" + btoa("svg Sing-box Collection"),
        "profile-update-interval": "4",
        "cache-control": "no-store, no-cache, must-revalidate",
        "Content-Disposition": "inline"
      }
    });
  }

  // 3. Generic Subscription (Base64 list of node URLs)
  const rawTextPayload = nodeLinks.join("\n");
  const base64Payload = btoa(rawTextPayload);
  const profileTitle = "svg Collection";

  return new Response(base64Payload, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "profile-title": "base64:" + btoa(profileTitle),
      "profile-update-interval": "4",
      "cache-control": "no-store, no-cache, must-revalidate",
      "Content-Disposition": "inline"
    }
  });
}