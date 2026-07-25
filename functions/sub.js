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

//ilpt2xhttp-firstx
vless://4e1e74bb-df9d-43ac-945e-890497369d7a@ilpt2.svgrn.work:443?type=xhttp&encryption=none&path=%2Fo8tXBUV0Qe&host=&mode=packet-up&security=tls#%ilpt2-xhttp

//ilpt2 latest iphone/mtsMsk bypass

vless://266185b0-844a-4d00-af3a-384660196d6f@ilpt2.svgrn.work:2053?fp=chrome&sni=ilpt2.svgrn.work&type=ws&path=%2FzG8sPvQe&host=ilpt2.svgrn.work&security=tls#ilpt2-04-07-2026

// Timeweb

vless://78fb87ba-2ae1-4bb2-8ea4-096e623cec96@timeweb.svgrn.work:443?type=xhttp&encryption=none&path=%2FBxuJlQBYBs&host=timeweb.svgrn.work&mode=packet-up&x_padding_bytes=100-1000&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D&security=tls#%TimewebMSK
  ];

//MyREALITYseltel

vless://57825bae-1d76-4be6-81ac-944734401557@seltel.svgrn.work:51732?security=reality&encryption=none&pbk=I_xfb96Z2i5Iz_HoSlD5PuxPNOP6AU33Qz5JR22xcyk&headerType=none&fp=chrome&type=tcp&sni=www.yandex.ru&sid=79f3f8d1cba04c49#MyREALITY%20seltel


vless://57825bae-1d76-4be6-81ac-944734401557@seltel.svgrn.work:51732?encryption=none&security=reality&sni=www.yandex.ru&fp=chrome&pbk=I_xfb96Z2i5Iz_HoSlD5PuxPNOP6AU33Qz5JR22xcyk&sid=79f3f8d1cba04c49&type=tcp#SELTEL-REALITY

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