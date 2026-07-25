 const nodeLinks = [

//ilpt2xhttp-firstx
"vless://4e1e74bb-df9d-43ac-945e-890497369d7a@ilpt2.svgrn.work:443?type=xhttp&encryption=none&path=%2Fo8tXBUV0Qe&host=&mode=packet-up&security=tls#%ilpt2-xhttp",

//ilpt2 latest iphone/mtsMsk bypass

"vless://266185b0-844a-4d00-af3a-384660196d6f@ilpt2.svgrn.work:2053?fp=chrome&sni=ilpt2.svgrn.work&type=ws&path=%2FzG8sPvQe&host=ilpt2.svgrn.work&security=tls#ilpt2-04-07-2026",

//MyREALITYseltel

"vless://57825bae-1d76-4be6-81ac-944734401557@seltel.svgrn.work:51732?security=reality&encryption=none&pbk=I_xfb96Z2i5Iz_HoSlD5PuxPNOP6AU33Qz5JR22xcyk&headerType=none&fp=chrome&type=tcp&sni=www.yandex.ru&sid=79f3f8d1cba04c49#MyREALITY-seltel",


"vless://57825bae-1d76-4be6-81ac-944734401557@seltel.svgrn.work:51732?encryption=none&security=reality&sni=www.yandex.ru&fp=chrome&pbk=I_xfb96Z2i5Iz_HoSlD5PuxPNOP6AU33Qz5JR22xcyk&sid=79f3f8d1cba04c49&type=tcp#SELTEL-REALITY",


// Timeweb

"vless://78fb87ba-2ae1-4bb2-8ea4-096e623cec96@timeweb.svgrn.work:443?type=xhttp&encryption=none&path=%2FBxuJlQBYBs&host=timeweb.svgrn.work&mode=packet-up&x_padding_bytes=100-1000&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D&security=tls#TimewebMSK"
  ];

  // Join into a single string separated by newlines
  const rawTextPayload = nodeLinks.join("\n");


  // 3. Base64 encode the payload (compatible with standard Node/V2Ray runtime)
  const base64Payload = btoa(rawTextPayload);


console.log (base64Payload)

