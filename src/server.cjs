const express = require("express");
const bodyParser = require("body-parser");
require("dotenv").config();
const { QdrantClient } = require("@qdrant/js-client-rest");
const { Groq } = require("groq-sdk");

const app = express();

app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "10mb" }));

app.use((error, req, res, next) => {
  if (error instanceof SyntaxError && error.status === 400 && "body" in error) {
    return res
      .status(400)
      .json({ error: "invalid_json", detail: error.message });
  }
  next();
});

const qdrant = new QdrantClient({
  url: process.env.QDRANT_URL,
  apiKey: process.env.QDRANT_API_KEY,
});

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

const COLLECTION = "policy_chunks";

// Get embeddings from Jina AI
async function getEmbeddings(texts, task = "retrieval.passage") {
  try {
    const response = await fetch("https://api.jina.ai/v1/embeddings", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.JINA_API_KEY}`,
      },
      body: JSON.stringify({
        model: "jina-embeddings-v3",
        dimensions: 1024,
        input: texts,
        task: task,
      }),
    });

    const data = await response.json();

    if (!response.ok || data.error) {
      throw new Error(`Jina API error: ${JSON.stringify(data.error || data)}`);
    }

    return data.data.map((d) => d.embedding);
  } catch (error) {
    console.error("Embedding error:", error.message);
    throw error;
  }
}

// Generate answer using Perplexity Sonar
async function generateAnswer(query, context) {
  try {
    const response = await fetch("https://api.perplexity.ai/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PERPLEXITY_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "sonar",
        messages: [
          {
            role: "system",
            content:
              "You are a helpful document assistant. Answer based ONLY on the provided context. Do not use external knowledge. Be concise and direct.",
          },
          {
            role: "user",
            content: `Context:\n${context}\n\nQuestion: ${query}\n\nAnswer:`,
          },
        ],
        max_tokens: 800,
        temperature: 0.1,
        top_p: 0.9,
        stream: false,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(`Perplexity error: ${response.status}`);
    }

    return data.choices[0].message.content;
  } catch (error) {
    console.error("Answer generation error:", error.message);
    throw error;
  }
}

// COMPLETE /check-website-safety ENDPOINT + ALL FUNCTIONS
app.post("/check-website-safety", async (req, res) => {
  console.log("\n" + "=".repeat(80));
  console.log("🚀 /check-website-safety ENDPOINT HIT!");
  console.log(`📅 Time: ${new Date().toISOString()}`);
  console.log("=".repeat(80));

  try {
    const apiKey = req.headers["x-api-key"] || req.header("X-Api-Key");
    console.log(`🔑 Received: "${apiKey?.substring(0, 10)}..."`);
    console.log(
      `🔑 Expected: "${process.env.BOT_API_KEY?.substring(0, 10)}..."`
    );

    if (apiKey !== process.env.BOT_API_KEY) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    console.log("✅ API KEY OK");

    const { url } = req.body || {};
    console.log(`🌐 URL: ${url}`);

    if (!url) {
      return res.status(400).json({ error: "URL required" });
    }

    // Extract domain
    let domain;
    try {
      const urlObj = new URL(url.startsWith("http") ? url : "https://" + url);
      domain = urlObj.hostname;
      console.log(`🔗 Domain: ${domain}`);
    } catch (e) {
      return res.status(400).json({ error: "Invalid URL" });
    }

    const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!vtApiKey) {
      console.log("⚠️ No VT key - FALLBACK");
      return res.json(performBasicSafetyCheck(url, domain));
    }

    console.log("📡 VirusTotal API call...");
    const vtResponse = await fetch(
      `https://www.virustotal.com/api/v3/domains/${domain}`,
      {
        method: "GET",
        headers: {
          "x-apikey": vtApiKey,
          Accept: "application/json",
        },
      }
    );

    console.log(`📡 VT Status: ${vtResponse.status}`);

    let analysis;
    if (vtResponse.ok) {
      const vtData = await vtResponse.json();
      console.log("✅ VT Data received, parsing...");
      analysis = parseVirusTotalV3(vtData, url, domain);
    } else {
      console.log(`⚠️ VT Error ${vtResponse.status}`);
      analysis = performBasicSafetyCheck(url, domain);
    }

    console.log(`📊 RESULT: ${analysis.status} | ${analysis.score}`);
    res.json(analysis);
  } catch (err) {
    console.error("💥 ERROR:", err.message);
    res.status(500).json({
      status: "error",
      score: 0,
      reasons: [],
      url: req.body?.url || "unknown",
      scan_details: {
        domain_age_days: null,
        ssl_valid: false,
        suspicious_redirects: false,
        category: "unknown",
      },
    });
  }
});

// ✅ FUNCTION 1: VirusTotal v3 Parser (UPDATED)
function parseVirusTotalV3(vtData, url, domain) {
  console.log("🔍 Parsing VirusTotal v3 data...");

  const data = vtData.data?.attributes || {};
  const stats = data.last_analysis_stats || {};
  const results = data.last_analysis_results || {};

  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;

  const reputation = data.reputation || 0;
  const creationDate = data.creation_date;
  const categories = data.categories || {};

  const reasons = [];
  let score = 100;
  let status = "safe";

  console.log(
    `📊 Raw stats: M:${malicious} S:${suspicious} H:${harmless} U:${undetected}`
  );

  // Domain Age
  let domainAgeDays = null;
  if (creationDate) {
    domainAgeDays = Math.floor((Date.now() / 1000 - creationDate) / 86400);
    if (domainAgeDays < 7) {
      reasons.push(`Domain age: ${domainAgeDays} days old`);
      score -= 30;
      status = "unsafe";
    } else if (domainAgeDays < 90) {
      reasons.push(`Domain age: ${domainAgeDays} days old`);
      score -= 15;
      if (status === "safe") status = "needs_review";
    }
  }

  // SSL Check
  const sslValid = url.startsWith("https://");
  if (!sslValid) {
    reasons.push("SSL certificate: Invalid");
    score -= 20;
    if (status === "safe") status = "needs_review";
  }

  // Threat Analysis
  if (malicious > 0) {
    reasons.push("Suspicious redirects detected");
    score -= malicious * 25;
    status = "unsafe";
  }

  if (suspicious > 0) {
    reasons.push("Suspicious redirects detected");
    score -= suspicious * 12;
    if (status === "safe") status = "needs_review";
  }

  // Categories
  const foundCategories = Object.keys(categories);
  const riskyCats = foundCategories.filter((cat) =>
    ["malware", "phishing", "spam", "abuse", "suspicious"].some((r) =>
      cat.toLowerCase().includes(r)
    )
  );

  if (riskyCats.length > 0) {
    reasons.push(`Found in "${riskyCats[0]}" category`);
    score -= 25;
    status = "unsafe";
  } else if (foundCategories.length > 0 && status !== "safe") {
    reasons.push(`Found in "${foundCategories[0]}" category`);
  }

  // Reputation
  if (reputation < -10) {
    score -= 20;
    status = "unsafe";
  }

  score = Math.max(0, Math.min(100, score));

  if (score >= 85 && status !== "unsafe") status = "safe";
  else if (score >= 60) status = "needs_review";
  else status = "unsafe";

  const result = {
    status,
    score: Math.round(score),
    reasons,
    url,
    scan_details: {
      domain_age_days: domainAgeDays,
      ssl_valid: sslValid,
      suspicious_redirects: malicious > 0 || suspicious > 0,
      category:
        foundCategories.length > 0 ? foundCategories[0] : "uncategorized",
      malicious,
      suspicious,
      harmless,
      undetected,
      reputation,
    },
  };

  console.log(`✅ Parse complete: ${result.status} | ${result.score}`);
  return result;
}

// ✅ FUNCTION 2: Basic Safety Check (UPDATED)
function performBasicSafetyCheck(url, domain) {
  console.log("🔧 Basic safety check...");
  const reasons = [];
  let score = 75;
  let status = "needs_review";

  const sslValid = url.startsWith("https://");
  if (!sslValid) {
    reasons.push("SSL certificate: Invalid");
    score -= 25;
  }

  const riskyTlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz"];
  if (riskyTlds.some((tld) => domain.endsWith(tld))) {
    reasons.push('Found in "suspicious domains" category');
    score -= 20;
    status = "unsafe";
  }

  return {
    status,
    score: Math.max(0, Math.round(score)),
    reasons,
    url,
    scan_details: {
      domain_age_days: null,
      ssl_valid: sslValid,
      suspicious_redirects: false,
      category: "unknown",
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      reputation: 0,
    },
  };
}

// POSH detection endpoint (Groq intent + classification)
app.post("/posh-detect", async (req, res) => {
  console.log("\n" + "=".repeat(60));
  console.log("🛡️ POSH DETECTION REQUEST");
  console.log("=".repeat(60));

  try {
    const apiKey = req.header("X-Api-Key");
    if (apiKey !== process.env.BOT_API_KEY) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const { text, channel, sender } = req.body || {};
    if (!text) {
      return res
        .status(400)
        .json({ error: "invalid_body", detail: "text is required" });
    }

    console.log(`👤 Sender: ${sender || "unknown"}`);
    console.log(`💬 Text: ${text}`);
    console.log(`#️⃣ Channel: ${channel || "unknown"}`);

    const chatCompletion = await groq.chat.completions.create({
      model: "openai/gpt-oss-120b",
      temperature: 0.2,
      max_completion_tokens: 200,
      stream: false,
      messages: [
        {
          role: "system",
          content:
            "You are a POSH (Prevention of Sexual Harassment) classifier for workplace chat messages.\n" +
            "Classify if the message violates POSH policy.\n\n" +
            "Return ONLY strict JSON in this format:\n" +
            "{\n" +
            '  "violation": true | false,\n' +
            '  "label": "safe" | "sexual_harassment" | "bullying" | "discrimination" | "other_misconduct",\n' +
            '  "reason": "short explanation",\n' +
            '  "risk_score": number from 0 to 100\n' +
            "}\n\n" +
            'If in doubt, set violation to false and label to "safe".',
        },
        {
          role: "user",
          content: `Message: "${text}"`,
        },
      ],
    });

    const llmRaw = chatCompletion.choices[0]?.message?.content?.trim() || "";
    console.log("🤖 Raw LLM:", llmRaw);

    let parsed;
    try {
      parsed = JSON.parse(llmRaw);
    } catch (e) {
      console.error("JSON parse failed, using safe fallback:", e.message);
      parsed = {
        violation: false,
        label: "safe",
        reason: "Model output was not valid JSON",
        risk_score: 0,
      };
    }

    // Normalise fields
    const responsePayload = {
      violation: Boolean(parsed.violation),
      label: parsed.label || "safe",
      reason: parsed.reason || "",
      risk_score: typeof parsed.risk_score === "number" ? parsed.risk_score : 0,
    };

    console.log("✅ POSH result:", responsePayload);
    console.log("=".repeat(60));

    res.json(responsePayload);
  } catch (err) {
    console.error("❌ POSH detect error:", err.message);
    res.status(500).json({
      violation: false,
      label: "safe",
      reason: "internal_error: " + err.message,
      risk_score: 0,
    });
  }
});

// // COMPLETE /check-website-safety ENDPOINT + ALL FUNCTIONS
// app.post("/check-website-safety", async (req, res) => {
//   console.log("\n" + "=".repeat(80));
//   console.log("🚀 /check-website-safety ENDPOINT HIT!");
//   console.log(`📅 Time: ${new Date().toISOString()}`);
//   console.log("=".repeat(80));

//   try {
//     const apiKey = req.headers["x-api-key"] || req.header("X-Api-Key");
//     console.log(`🔑 Received: "${apiKey?.substring(0, 10)}..."`);
//     console.log(
//       `🔑 Expected: "${process.env.BOT_API_KEY?.substring(0, 10)}..."`
//     );

//     if (apiKey !== process.env.BOT_API_KEY) {
//       return res.status(401).json({ error: "Unauthorized" });
//     }
//     console.log("✅ API KEY OK");

//     const { url } = req.body || {};
//     console.log(`🌐 URL: ${url}`);

//     if (!url) {
//       return res.status(400).json({ error: "URL required" });
//     }

//     // Extract domain
//     let domain;
//     try {
//       const urlObj = new URL(url.startsWith("http") ? url : "https://" + url);
//       domain = urlObj.hostname;
//       console.log(`🔗 Domain: ${domain}`);
//     } catch (e) {
//       return res.status(400).json({ error: "Invalid URL" });
//     }

//     const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
//     if (!vtApiKey) {
//       console.log("⚠️ No VT key - FALLBACK");
//       return res.json(performBasicSafetyCheck(url, domain));
//     }

//     console.log("📡 VirusTotal API call...");
//     const vtResponse = await fetch(
//       `https://www.virustotal.com/api/v3/domains/${domain}`,
//       {
//         method: "GET",
//         headers: {
//           "x-apikey": vtApiKey,
//           Accept: "application/json",
//         },
//       }
//     );

//     console.log(`📡 VT Status: ${vtResponse.status}`);

//     let analysis;
//     if (vtResponse.ok) {
//       const vtData = await vtResponse.json();
//       console.log("✅ VT Data received, parsing...");
//       analysis = parseVirusTotalV3(vtData, url, domain); // ✅ NOW DEFINED
//     } else {
//       console.log(`⚠️ VT Error ${vtResponse.status}`);
//       analysis = performBasicSafetyCheck(url, domain);
//     }

//     console.log(`📊 RESULT: ${analysis.status} | ${analysis.score}`);
//     res.json(analysis);
//   } catch (err) {
//     console.error("💥 ERROR:", err.message);
//     res.status(500).json({
//       status: "error",
//       score: 0,
//       reasons: ["Server error"],
//       url: req.body?.url || "unknown",
//     });
//   }
// });

// // ✅ FUNCTION 1: VirusTotal v3 Parser (YOUR CODE - FIXED)
// function parseVirusTotalV3(vtData, url, domain) {
//   console.log("🔍 Parsing VirusTotal v3 data...");

//   const data = vtData.data?.attributes || {};
//   const stats = data.last_analysis_stats || {};
//   const results = data.last_analysis_results || {};

//   const malicious = stats.malicious || 0;
//   const suspicious = stats.suspicious || 0;
//   const harmless = stats.harmless || 0;
//   const undetected = stats.undetected || 0;

//   const reputation = data.reputation || 0;
//   const creationDate = data.creation_date;
//   const categories = data.categories || {};

//   const reasons = [];
//   let score = 100;
//   let status = "safe";

//   console.log(
//     `📊 Raw stats: M:${malicious} S:${suspicious} H:${harmless} U:${undetected}`
//   );

//   // Threat Analysis
//   if (malicious > 0) {
//     reasons.push(`🚨 ${malicious} engines detected MALWARE`);
//     const engines = Object.entries(results)
//       .filter(([_, r]) => r?.category === "malicious")
//       .slice(0, 3)
//       .map(([e]) => e);
//     if (engines.length) reasons.push(`   Engines: ${engines.join(", ")}`);
//     score -= malicious * 25;
//     status = "unsafe";
//   }

//   if (suspicious > 0) {
//     reasons.push(`⚠️ ${suspicious} engines detected SUSPICIOUS`);
//     score -= suspicious * 12;
//     if (status === "safe") status = "needs_review";
//   }

//   // Domain Age ✅ FIXED
//   if (creationDate) {
//     const ageDays = Math.floor((Date.now() / 1000 - creationDate) / 86400);
//     if (ageDays < 7) {
//       reasons.push(`🆕 Domain created ${ageDays} days ago (NEW)`);
//       score -= 30;
//       status = "unsafe";
//     } else if (ageDays < 90) {
//       reasons.push(`📅 Domain age: ${ageDays} days`);
//       score -= 15;
//       if (status === "safe") status = "needs_review";
//     }
//   }

//   // Reputation
//   if (reputation < -10) {
//     reasons.push(`📉 Reputation: ${reputation}`);
//     score -= 20;
//     status = "unsafe";
//   }

//   // Categories
//   const riskyCats = Object.keys(categories).filter((cat) =>
//     ["malware", "phishing", "spam", "abuse"].some((r) => cat.includes(r))
//   );
//   if (riskyCats.length) {
//     reasons.push(`🏷️ Risky categories: ${riskyCats.join(", ")}`);
//     score -= 25;
//     status = "unsafe";
//   }

//   // HTTPS
//   if (!url.startsWith("https://")) {
//     reasons.push("🔓 No HTTPS");
//     score -= 15;
//   }

//   score = Math.max(0, Math.min(100, score));

//   if (score >= 85 && status !== "unsafe") status = "safe";
//   else if (score >= 60) status = "needs_review";
//   else status = "unsafe";

//   if (reasons.length === 0) {
//     reasons.push(`✅ Clean: ${harmless} harmless, ${undetected} undetected`);
//     reasons.push(
//       `📊 Scanned by ${malicious + suspicious + harmless + undetected} engines`
//     );
//   }

//   const result = {
//     status,
//     score: Math.round(score),
//     reasons,
//     url,
//     scan_details: {
//       malicious,
//       suspicious,
//       harmless,
//       undetected,
//       reputation,
//       domain_age_days: creationDate
//         ? Math.floor((Date.now() / 1000 - creationDate) / 86400)
//         : null,
//     },
//   };

//   console.log(`✅ Parse complete: ${result.status} | ${result.score}`);
//   return result;
// }

// // ✅ FUNCTION 2: Basic Safety Check
// function performBasicSafetyCheck(url, domain) {
//   console.log("🔧 Basic safety check...");
//   const reasons = ["⚠️ Basic analysis (VirusTotal unavailable)"];
//   let score = 75;
//   let status = "needs_review";

//   if (!url.startsWith("https://")) {
//     reasons.push("🔓 Uses HTTP");
//     score -= 25;
//   }

//   const riskyTlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz"];
//   if (riskyTlds.some((tld) => domain.endsWith(tld))) {
//     reasons.push("⚠️ Risky TLD");
//     score -= 20;
//     status = "unsafe";
//   }

//   return {
//     status,
//     score: Math.max(0, Math.round(score)),
//     reasons,
//     url,
//     scan_details: {
//       malicious: 0,
//       suspicious: 0,
//       harmless: 0,
//       undetected: 0,
//       reputation: 0,
//       domain_age_days: null,
//     },
//   };
// }

// // POSH detection endpoint (Groq intent + classification)
// app.post("/posh-detect", async (req, res) => {
//   console.log("\n" + "=".repeat(60));
//   console.log("🛡️ POSH DETECTION REQUEST");
//   console.log("=".repeat(60));

//   try {
//     const apiKey = req.header("X-Api-Key");
//     if (apiKey !== process.env.BOT_API_KEY) {
//       return res.status(401).json({ error: "unauthorized" });
//     }

//     const { text, channel, sender } = req.body || {};
//     if (!text) {
//       return res
//         .status(400)
//         .json({ error: "invalid_body", detail: "text is required" });
//     }

//     console.log(`👤 Sender: ${sender || "unknown"}`);
//     console.log(`💬 Text: ${text}`);
//     console.log(`#️⃣ Channel: ${channel || "unknown"}`);

//     const chatCompletion = await groq.chat.completions.create({
//       model: "openai/gpt-oss-120b",
//       temperature: 0.2,
//       max_completion_tokens: 200,
//       stream: false,
//       messages: [
//         {
//           role: "system",
//           content:
//             "You are a POSH (Prevention of Sexual Harassment) classifier for workplace chat messages.\n" +
//             "Classify if the message violates POSH policy.\n\n" +
//             "Return ONLY strict JSON in this format:\n" +
//             "{\n" +
//             '  "violation": true | false,\n' +
//             '  "label": "safe" | "sexual_harassment" | "bullying" | "discrimination" | "other_misconduct",\n' +
//             '  "reason": "short explanation",\n' +
//             '  "risk_score": number from 0 to 100\n' +
//             "}\n\n" +
//             'If in doubt, set violation to false and label to "safe".',
//         },
//         {
//           role: "user",
//           content: `Message: "${text}"`,
//         },
//       ],
//     });

//     const llmRaw = chatCompletion.choices[0]?.message?.content?.trim() || "";
//     console.log("🤖 Raw LLM:", llmRaw);

//     let parsed;
//     try {
//       parsed = JSON.parse(llmRaw);
//     } catch (e) {
//       console.error("JSON parse failed, using safe fallback:", e.message);
//       parsed = {
//         violation: false,
//         label: "safe",
//         reason: "Model output was not valid JSON",
//         risk_score: 0,
//       };
//     }

//     // Normalise fields
//     const responsePayload = {
//       violation: Boolean(parsed.violation),
//       label: parsed.label || "safe",
//       reason: parsed.reason || "",
//       risk_score: typeof parsed.risk_score === "number" ? parsed.risk_score : 0,
//     };

//     console.log("✅ POSH result:", responsePayload);
//     console.log("=".repeat(60));

//     res.json(responsePayload);
//   } catch (err) {
//     console.error("❌ POSH detect error:", err.message);
//     res.status(500).json({
//       violation: false,
//       label: "safe",
//       reason: "internal_error: " + err.message,
//       risk_score: 0,
//     });
//   }
// });

// Intent classification
app.post("/classify-intent", async (req, res) => {
  try {
    const apiKey = req.header("X-Api-Key");
    if (apiKey !== process.env.BOT_API_KEY) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: "invalid_body" });
    }

    const chatCompletion = await groq.chat.completions.create({
      messages: [
        {
          role: "system",
          content: `Classify intent as:
1. "casual" - greetings, small talk (respond with friendly message)
2. "document_query" - questions requiring document search

Respond with JSON:
{"intent": "casual", "response": "message"}
OR
{"intent": "document_query"}`,
        },
        {
          role: "user",
          content: message,
        },
      ],
      model: "openai/gpt-oss-20b",
      temperature: 0.3,
      max_completion_tokens: 150,
      stream: false,
    });

    const llmResponse = chatCompletion.choices[0]?.message?.content.trim();

    let classification;
    try {
      classification = JSON.parse(llmResponse);
    } catch (e) {
      classification = { intent: "document_query" };
    }

    res.json(classification);
  } catch (err) {
    console.error("Classification error:", err.message);
    res.json({ intent: "document_query" });
  }
});

// Recreate collection
app.post("/recreate-collection", async (req, res) => {
  try {
    const apiKey = req.header("X-Api-Key");
    if (apiKey !== process.env.BOT_API_KEY) {
      return res.status(401).json({ error: "unauthorized" });
    }

    try {
      await qdrant.deleteCollection(COLLECTION);
    } catch (e) {
      // Collection doesn't exist
    }

    await qdrant.createCollection(COLLECTION, {
      vectors: {
        size: 1024,
        distance: "Cosine",
      },
    });

    res.json({
      status: "ok",
      collection: COLLECTION,
      dimensions: 1024,
    });
  } catch (err) {
    console.error("Recreate error:", err.message);
    res.status(500).json({
      error: "internal_error",
      detail: err.message,
    });
  }
});

// Index chunks
app.post("/index-chunks", async (req, res) => {
  try {
    const apiKey = req.header("X-Api-Key");
    if (apiKey !== process.env.BOT_API_KEY) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const { org_id, doc_name, chunks } = req.body;

    if (!org_id || !doc_name || !chunks) {
      return res.status(400).json({ error: "invalid_body" });
    }

    const chunksArray = Array.isArray(chunks) ? chunks : JSON.parse(chunks);

    if (chunksArray.length === 0) {
      return res.status(400).json({ error: "no_chunks" });
    }

    const chunkTexts = chunksArray.map((c) => c.chunk_text);
    const vectors = await getEmbeddings(chunkTexts, "retrieval.passage");

    if (vectors.length !== chunksArray.length) {
      return res.status(500).json({ error: "embedding_mismatch" });
    }

    const baseId = Date.now();

    const points = chunksArray.map((c, i) => ({
      id: baseId + i,
      vector: vectors[i],
      payload: {
        org_id,
        doc_name,
        chunk_id: c.chunk_id,
        chunk_text: c.chunk_text,
      },
    }));

    await qdrant.upsert(COLLECTION, { points });

    res.json({ status: "ok", indexed: chunksArray.length });
  } catch (err) {
    console.error("Index error:", err.message);
    res.status(500).json({
      error: "internal_error",
      detail: err.message,
    });
  }
});

// Query endpoint
app.post("/query", async (req, res) => {
  try {
    const apiKey = req.header("X-Api-Key");
    if (apiKey !== process.env.BOT_API_KEY) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const { org_id, question } = req.body;

    if (!org_id || !question) {
      return res.status(400).json({ error: "invalid_body" });
    }

    const queryVectors = await getEmbeddings([question], "retrieval.query");
    const queryVector = queryVectors[0];

    const searchResults = await qdrant.search(COLLECTION, {
      vector: queryVector,
      limit: 3,
    });

    if (searchResults.length === 0) {
      return res.json({
        status: "ok",
        answer: "I couldn't find relevant information in your documents.",
        sources: [],
      });
    }

    const context = searchResults
      .map(
        (r, i) => `[${i + 1}] ${r.payload.doc_name}:\n${r.payload.chunk_text}`
      )
      .join("\n\n");

    const answer = await generateAnswer(question, context);

    const responseData = {
      status: "ok",
      answer: answer,
      sources: searchResults.map((r) => ({
        doc_name: r.payload.doc_name,
        chunk_text: r.payload.chunk_text.substring(0, 200) + "...",
        score: r.score,
      })),
    };

    res.json(responseData);
  } catch (err) {
    console.error("Query error:", err.message);
    res.status(500).json({
      error: "internal_error",
      detail: err.message,
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 RAG Backend: http://localhost:${PORT}`);
});
