const allowedDomains = [
  'https://catchthefever.com/',
  'https://www.catchthefever.com'
];

const CLIENT_TOKEN = process.env.CLIENT_TOKEN;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

function sanitizeDataLayer(dataLayer) {
  const sensitiveKeys = [
    'email', 'name', 'phone', 'number', 'address'
  ];
  return dataLayer.map(obj =>
    Object.fromEntries(
      Object.entries(obj).filter(
        ([key]) => !sensitiveKeys.includes(key.toLowerCase())
      )
    )
  );
}

export default async function handler(req, res) {
  const referer = req.headers.referer || '';
  const allowedOrigin = allowedDomains.find(domain => referer.startsWith(domain));

  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-client-token');
  res.setHeader('Access-Control-Allow-Origin', allowedOrigin || '');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  if (!allowedOrigin) {
    return res.status(403).json({ error: "Forbidden - invalid referer" });
  }

  const clientToken = req.headers['x-client-token'];
  if (!clientToken || clientToken !== CLIENT_TOKEN) {
    return res.status(403).json({ error: "Forbidden - invalid token" });
  }

  let sanitizedDataLayer;

  if (Array.isArray(req.body.datalayer) && req.body.datalayer.length) {
    if (req.body.datalayer.length > 1000) {
      return res.status(413).json({ error: "Payload too large" });
    }
    sanitizedDataLayer = sanitizeDataLayer(req.body.datalayer);
  } else {
    sanitizedDataLayer = [{
      info: req.body.info || "no_dataLayer",
      url: req.body.url || "",
      timestamp: req.body.timestamp || new Date().toISOString()
    }];
  }

  const response = await fetch(`${SUPABASE_URL}/rest/v1/datalayer`, {
    method: 'POST',
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ datalayer: sanitizedDataLayer })
  });

  if (!response.ok) {
    return res.status(500).json({ error: "Failed to save to Supabase" });
  }

  return res.status(200).json({ success: true });
}
