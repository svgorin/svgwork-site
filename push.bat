git add .
git commit -m "subs.js"
git push
"C:\Program Files\PuTTY\plink.exe" -batch -hostkey "ssh-ed25519 255 SHA256:3oWGtg6CjATOylTPZxrb3nl7jPmenzqpJGJJj4gyFlo" -i "G:\My Drive\VPS\timeweb\priv.ppk" root@timeweb.svgrn.work "bash /opt/svgwork-site/deploy_sub_server.sh"
