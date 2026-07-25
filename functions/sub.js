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
    "vless://uuid-1@1.2.3.4:443?type=ws&security=tls#Primary-Node",
    "vless://uuid-2@5.6.7.8:443?type=grpc&security=reality&sni=google.com&pbk=...#Backup-REALITY"
  ];

  // Join into a single string separated by newlines
  const rawTextPayload = nodeLinks.join("\n");

  // 3. Base64 encode the payload (compatible with standard Node/V2Ray runtime)
  const base64Payload = btoa(rawTextPayload);

  // 4. Return response with V2Ray subscription headers
  const profileTitle = "Personal Feed";

  return new Response(base64Payload, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      // Sets the subscription profile name in v2rayTUN / Incy / v2rayN
      "profile-title": "base64:" + btoa(profileTitle),
      // Instructs the client to auto-sync every 4 hours
      "profile-update-interval": "4",
      // Prevents aggressive browser/CDN caching so client updates are instant
      "cache-control": "no-store, no-cache, must-revalidate"
    }
  });
}