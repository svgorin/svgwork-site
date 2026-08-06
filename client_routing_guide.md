# Client Setup Guide: How to Enable Split-Tunneling (Routing)

This guide shows how your friends can configure their client applications so that **blocked services** (YouTube, Telegram, Instagram, Facebook, and RKN-blocked sites) go through the VPN, while **Russian sites and services** (State portals, banking apps, local media) open directly (without VPN) for maximum speed and compatibility.

---

## 🚀 Option 1: Automatic Routing (Zero Configuration)
If they use **Hiddify Next** or **Karing**, routing rules are dynamically delivered via the subscription server! 

1. Simply copy the subscription link: `http://<YOUR_DOMAIN>/sub?key=Im7R9FYpBFwXmKX6`
2. Import it into **Hiddify Next** or **Karing**.
3. The server will detect their client and deliver a pre-configured routing ruleset. No manual app adjustments are required!

---

## 🛠️ Option 2: Manual Routing Configuration (By Client App)
If they are using standard VLESS links or other client apps, they can configure the routing rules inside the app settings:

### 1. v2RayTun (iOS & Android)
v2RayTun emulates Xray-core routing directly:
1. Open **v2RayTun** and tap the **Menu (☰)** icon in the top-left corner.
2. Tap **Settings**.
3. Under the **Routing** section, tap **Routing Mode** and select **Rule / Custom Rules**.
4. Go to the Custom Rules editor and add the following rules:
   * **Rule 1 (Direct - bypass VPN):**
     * Outbound: `direct`
     * Domains: `geosite:russia`, `geosite:category-gov-ru`
     * IPs: `geoip:ru`
   * **Rule 2 (Proxy - route through VPN):**
     * Outbound: `proxy`
     * Domains: `geosite:antifilter-community`, `geosite:youtube`, `geosite:facebook`, `geosite:instagram`, `geosite:telegram`
     * IPs: `geoip:antifilter-community`
5. Save settings and connect.

---

### 2. v2rayNG (Android)
1. Open **v2rayNG**, tap **Menu (☰)**, and select **Settings**.
2. Scroll to the **Routing** section and set **Routing Mode** to **Custom rules**.
3. Configure the custom categories:
   * Tap **Direct URL** and input: `geosite:russia,geosite:category-gov-ru`
   * Tap **Direct IP** and input: `geoip:ru`
   * Tap **Proxy URL** and input: `geosite:antifilter-community,geosite:youtube,geosite:facebook,geosite:instagram,geosite:telegram`
   * Tap **Proxy IP** and input: `geoip:antifilter-community`
4. Tap Save/Confirm, then restart the connection.

---

### 3. Hiddify Next (Universal)
If they did not use the auto-routing subscription link and imported raw VLESS links instead:
1. Open **Hiddify**, go to **Settings** (gear icon) -> **Config Settings**.
2. Tap **Routing**.
3. Under **Route Mode**, select **Only Blocked (Russia)**.
4. *Tip:* Under **Fragment**, toggle it to **Enabled** to bypass ISP handshake fingerprint drops.

---

### 4. Karing (Windows, iOS, Android)
If they did not use the auto-routing subscription link and imported raw VLESS links instead:
1. Open **Karing**, tap **Settings** -> **Routing**.
2. Set mode to **Rule**.
3. Go to **Rulesets** -> tap the **+** (add ruleset).
4. Tap **Online Ruleset** and search/select **Russia Blocked** or **antifilter**. Set its action to **Proxy**.
5. Search/select **Russia Bypass (Geosite Russia)** and set its action to **Direct**.

---

### 5. Nekoray / Nekobox (Windows Desktop)
1. In Nekoray, go to the top menu: **Preferences** -> **Routing Setting**.
2. Select the **Simple Route** tab.
3. Set **Route Mode** to **Rule**.
4. Configure the parameters:
   * **Direct Domains:** `geosite:russia,geosite:category-gov-ru`
   * **Direct IPs:** `geoip:ru`
   * **Proxy Domains:** `geosite:youtube,geosite:telegram,geosite:facebook,geosite:instagram,geosite:antifilter-community`
   * **Proxy IPs:** `geoip:antifilter-community`
5. Check the **Bypass LAN** box and click **OK**.
