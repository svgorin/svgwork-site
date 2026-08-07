# svgwork-site: Node.js Subscription Feeder

A self-contained, low-overhead Node.js subscription server for managing VLESS and Shadowsocks (Outline) connections with client-side split-tunneling (routing) for bypassing Russian censorship (RKN/TSPU).

---

## 🛠️ Design & Deployment Architecture
* **Decentralized Node.js:** Running natively on port `33130` on any Linux VPS. Safe from Cloudflare-targeted blockages.
* **Multi-Server Resilient:** Can be deployed to multiple backup nodes (including cheap Russian VPS instances) to ensure high availability of the subscription link.
* **Git-Ops Updates:** Manage VLESS/Shadowsocks links locally, `git push` to your private GitHub repo, and run `git pull && sudo systemctl restart simple_sub` on the servers to update all your friends' configs instantly.

---

## 🚀 Installation & Update Playbook

### 1. Initial Setup on a New Server:
```bash
# Clone the repository
git clone <YOUR_GITHUB_REPO_URL> /var/www/svgwork-site
cd /var/www/svgwork-site

# Make scripts executable
chmod +x install_service.sh

# Install and start the service
sudo ./install_service.sh
```

### 2. Updating Links (Git-Ops workflow):
On your local machine:
1. Open [`simple_sub.js`](file:///D:/prj/svgwork-site/simple_sub.js).
2. Modify the `nodeLinks` array with new/updated connection strings.
3. Commit and push:
   ```bash
   git add simple_sub.js
   git commit -m "Update subscription nodes"
   git push origin main
   ```

On the server(s):
```bash
cd /var/www/svgwork-site
git pull
sudo systemctl restart simple_sub
```

---

## 🧭 Subscription URL Structure
The server dynamically formats rules based on the client's `User-Agent` or the explicit query parameter `?format=`:

* **Clash/Mihomo** (`?format=clash`): Returns YAML ruleset routing RKN-blocked resources through the VPN, and Russian sites directly.
* **Sing-box/Hiddify/Karing** (`?format=sing-box`): Returns JSON configuration compiling remote SRS rulesets for automatic split-tunneling.
* **v2RayTun/Generic** (`?format=txt` or none): Returns base64-encoded VLESS/Shadowsocks URLs.

---

## 🔑 GitHub Authentication (Private Repo Setup)
Since the repository is private to protect your access keys, configure one of the following authentication methods on your VPS nodes:

### Option A: SSH Deploy Keys (Recommended)
1. **Generate SSH Key on VPS:**
   ```bash
   ssh-keygen -t ed25519 -C "vps-deploy-key" -N "" -f ~/.ssh/id_ed25519_github
   ```
2. **Configure SSH Config (`~/.ssh/config`):**
   ```text
   Host github.com
     IdentityFile ~/.ssh/id_ed25519_github
     User git
   ```
3. **Add to GitHub:**
   Print and copy the public key:
   ```bash
   cat ~/.ssh/id_ed25519_github.pub
   ```
   Go to your GitHub repository -> **Settings** -> **Deploy Keys** -> **Add deploy key** and paste it (keep *Allow write access* unchecked).
4. **Clone Repository:**
   ```bash
   git clone git@github.com:username/svgwork-site.git /var/www/svgwork-site
   ```

### Option B: Personal Access Token (PAT)
1. Go to GitHub **Settings -> Developer Settings -> Personal Access Tokens -> Fine-grained tokens** and generate a token with **Read-only** permissions to repository contents.
2. Clone using the token:
   ```bash
   git clone https://<YOUR_PAT>@github.com/username/svgwork-site.git /var/www/svgwork-site
   ```





  ### Future Updates:

  Whenever you push new node updates to GitHub, you can just log in and re-run /opt/svgwork-site's pull rules, or run
  deploy_sub_server.sh again to refresh and restart the service!


bash /opt/svgwork-site/deploy_sub_server.sh


  or

    cd /opt/svgwork-site/
    ./deploy_sub_server.sh



