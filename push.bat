node sync_nodes.js
git add .
git commit -m "subs.js"
git push
"C:\Program Files\PuTTY\plink.exe" -batch -hostkey "ssh-ed25519 255 SHA256:BPgTj8ldnT/s09mdwlT/CtvXrZlTsgv6cv+Yp4kDV2Q" -i "G:\My Drive\VPS\selectel2\AlgoSelectel\92.53.70.164\Keys\priv.ppk" root@seltel.svgrn.work "bash /opt/svgwork-site/deploy_sub_server.sh"

