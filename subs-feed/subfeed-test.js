// Test script to verify subscription endpoint locally or against remote Pages/Worker
const SUB_URL = "https://09450419.svgwork-site.pages.dev/sub?key=YOUR_SECRET_KEY";

async function testSubscription() {
  console.log(`Sending request to: ${SUB_URL}\n`);

  try {
    const response = await fetch(SUB_URL, {
      headers: {
        // Mimic a standard V2Ray client user-agent
        "User-Agent": "v2rayTUN/1.0.0"
      }
    });

    console.log(`Status Code: ${response.status} ${response.statusText}`);

    if (!response.ok) {
      console.error(`? Request failed with status ${response.status}`);
      return;
    }

    // Parse subscription headers
    const profileTitleHeader = response.headers.get("profile-title");
    const updateInterval = response.headers.get("profile-update-interval");

    if (profileTitleHeader) {
      // Profile titles in headers are usually base64-encoded with a prefix (e.g. "base64:...")
      const titleClean = profileTitleHeader.replace(/^base64:/, "");
      const decodedTitle = Buffer.from(titleClean, "base64").toString("utf-8");
      console.log(`Profile Title: ${decodedTitle}`);
    }

    if (updateInterval) {
      console.log(`Sync Interval: Every ${updateInterval} hours`);
    }

    // Parse body payload
    const rawBody = await response.text();
    console.log(`\nRaw Payload Received (${rawBody.length} bytes):`);
    console.log(rawBody.trim());

    // Decode Base64 payload
    const decodedPayload = Buffer.from(rawBody.trim(), "base64").toString("utf-8");
    const nodeLinks = decodedPayload.split("\n").filter(line => line.trim().length > 0);

    console.log(`\n? Successfully parsed ${nodeLinks.length} node(s):\n`);
    nodeLinks.forEach((link, idx) => {
      console.log(`  [${idx + 1}] ${link}`);
    });

  } catch (err) {
    console.error("? Failed to fetch subscription:", err.message);
  }
}

testSubscription();