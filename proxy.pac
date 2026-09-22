// ============================================================================
// Proxy Auto-Configuration (PAC) Script
// Routes *.ru domains and specified array of domains through designated proxy
// All other traffic goes DIRECT
// ============================================================================

// --- 1. Target Proxy Configuration ---
// Formats:
// "PROXY host:port" (HTTP Proxy)
// "SOCKS5 host:port; SOCKS host:port" (SOCKS5 Proxy)
// Multiple fallbacks can be separated by semicolons
var PROXY_SERVER = "SOCKS5 77.110.105.81:1080; SOCKS 77.110.105.81:1080; PROXY 77.110.105.81:8080; PROXY 77.110.105.81:3128; DIRECT";

// --- 2. Custom Domains Array ---
// Add any additional domains or services that should be routed through the proxy
var proxyDomains = [
  // Russian social & media platforms
  "vk.com",
  "vk.me",
  "userapi.com",
  "ok.ru",
  "mail.ru",
  "my.mail.ru",
  "dzen.ru",
  "rutube.ru",
  "pikabu.ru",
  "habr.com",
  "yaplakal.com",

  // Search & Portals
  "yandex.ru",
  "ya.ru",
  "yandex.net",
  "yastatic.net",
  "rambler.ru",

  // Government & Municipal services
  "gosuslugi.ru",
  "gosuslugi.org",
  "mos.ru",
  "spb.ru",
  "nalog.gov.ru",
  "nalog.ru",
  "cbr.ru",
  "customs.gov.ru",
  "pfr.gov.ru",
  "sfr.gov.ru",
  "zakupki.gov.ru",
  "sudrf.ru",

  // Banking & Financial services
  "sberbank.ru",
  "sber.ru",
  "sberbank.com",
  "online.sberbank.ru",
  "tbank.ru",
  "tinkoff.ru",
  "vtb.ru",
  "alfabank.ru",
  "gazprombank.ru",
  "raiffeisen.ru",
  "rshb.ru",
  "psbank.ru",
  "sovcombank.ru",
  "open.ru",
  "mirpay.ru",
  "nspk.ru",

  // E-Commerce & Marketplaces
  "avito.ru",
  "ozon.ru",
  "wildberries.ru",
  "market.yandex.ru",
  "megamarket.ru",
  "dns-shop.ru",
  "mvideo.ru",
  "eldorado.ru",
  "aliexpress.ru",

  // Telecom & Infrastructure
  "mts.ru",
  "megafon.ru",
  "beeline.ru",
  "t2.ru",
  "tele2.ru",
  "rostelecom.ru",
  "rt.ru",
  "yota.ru",

  // News & Media
  "rbc.ru",
  "ria.ru",
  "tass.ru",
  "kommersant.ru",
  "vedomosti.ru",
  "lenta.ru",
  "gazeta.ru",
  "interfax.ru",

  // Maps, Navigation & Travel
  "2gis.ru",
  "2gis.com",
  "auto.ru",
  "rzd.ru",
  "aeroflot.ru",
  "yandex.maps",
  "kinopoisk.ru",
  "ivi.ru",
  "okko.tv"
];

// --- 3. PAC Resolution Logic ---
function FindProxyForURL(url, host) {
  // Convert host to lowercase for uniform matching
  if (!host) {
    return "DIRECT";
  }
  host = host.toLowerCase();

  // 1. Bypass proxy for local / intranet hostnames
  if (isPlainHostName(host) ||
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "::1" ||
      shExpMatch(host, "10.*") ||
      shExpMatch(host, "192.168.*") ||
      shExpMatch(host, "172.16.*") ||
      shExpMatch(host, "172.17.*") ||
      shExpMatch(host, "172.18.*") ||
      shExpMatch(host, "172.19.*") ||
      shExpMatch(host, "172.2*") ||
      shExpMatch(host, "172.30.*") ||
      shExpMatch(host, "172.31.*")) {
    return "DIRECT";
  }

  // 2. Route all *.ru, *.su, and *.рф (punycode xn--p1ai) domains to proxy
  if (dnsDomainIs(host, ".ru") || host === "ru" || shExpMatch(host, "*.ru") ||
      dnsDomainIs(host, ".su") || host === "su" || shExpMatch(host, "*.su") ||
      dnsDomainIs(host, ".xn--p1ai") || host === "xn--p1ai" || shExpMatch(host, "*.xn--p1ai")) {
    return PROXY_SERVER;
  }

  // 3. Match against the custom domains array (matches exact or any subdomain)
  for (var i = 0; i < proxyDomains.length; i++) {
    var domain = proxyDomains[i].toLowerCase();
    if (host === domain || dnsDomainIs(host, "." + domain)) {
      return PROXY_SERVER;
    }
  }

  // 4. Default: all other internet traffic goes DIRECT without proxy
  return "DIRECT";
}
