const fs = require('fs');
const path = require('path');

const nodeLinksPath = path.join(__dirname, 'node_links.js');
const subJsPath = path.join(__dirname, 'functions', 'sub.js');

const nodeLinks = require(nodeLinksPath);
let subJs = fs.readFileSync(subJsPath, 'utf8');

const replacement = `  // 2. Define your node URLs (one per line)\n  const nodeLinks = ${JSON.stringify(nodeLinks, null, 4)};`;

subJs = subJs.replace(/\/\/ 2\. Define your node URLs[\s\S]*?const nodeLinks = \[[\s\S]*?\];/, replacement);

fs.writeFileSync(subJsPath, subJs, 'utf8');
console.log(`[sync_nodes] Successfully synced ${nodeLinks.length} nodes from node_links.js to functions/sub.js`);
