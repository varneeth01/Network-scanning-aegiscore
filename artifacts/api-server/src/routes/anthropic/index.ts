import { Router } from "express";
import { openrouter } from "@workspace/integrations-openrouter-ai";
import crypto from "crypto";

const router = Router();

interface Message {
  id: number;
  conversationId: number;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
}

interface Conversation {
  id: number;
  title: string;
  createdAt: string;
}

const convStore = new Map<number, Conversation>();
const msgStore = new Map<number, Message[]>();
let convIdSeq = 1;
let msgIdSeq = 1;

const SYSTEM_PROMPT = `You are AegisCore, an expert cybersecurity AI analyst specializing in:
- Malware behavioral analysis and classification
- Network traffic analysis (Wireshark/PCAP inspection)
- Zero-day vulnerability detection and exploitation pattern recognition
- System call analysis and behavioral profiling
- Threat intelligence and IOC extraction

When analyzing data:
1. Identify suspicious patterns, IOCs, and behavioral anomalies
2. Classify threats by type (ransomware, RAT, botnet, trojan, spyware, etc.)
3. Detect potential zero-day exploits by comparing against known vulnerability patterns
4. Extract network indicators (C2 IPs, domains, ports, protocols)
5. Provide actionable remediation recommendations
6. Give confidence scores for each detection

Format responses with clear sections: THREAT ASSESSMENT, IOCs DETECTED, BEHAVIORAL ANALYSIS, NETWORK INDICATORS, ZERO-DAY INDICATORS, RECOMMENDATIONS.`;

router.get("/anthropic/conversations", (_req, res) => {
  const list = Array.from(convStore.values()).sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
  res.json(list);
});

router.post("/anthropic/conversations", (req, res) => {
  const { title } = req.body;
  const id = convIdSeq++;
  const conv: Conversation = {
    id,
    title: title ?? `Analysis ${crypto.randomUUID().slice(0, 6)}`,
    createdAt: new Date().toISOString(),
  };
  convStore.set(id, conv);
  msgStore.set(id, []);
  res.status(201).json(conv);
});

router.get("/anthropic/conversations/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  const conv = convStore.get(id);
  if (!conv) { res.status(404).json({ error: "Conversation not found" }); return; }
  const messages = msgStore.get(id) ?? [];
  res.json({ ...conv, messages });
});

router.delete("/anthropic/conversations/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!convStore.has(id)) { res.status(404).json({ error: "Not found" }); return; }
  convStore.delete(id);
  msgStore.delete(id);
  res.status(204).end();
});

router.get("/anthropic/conversations/:id/messages", (req, res) => {
  const id = parseInt(req.params.id, 10);
  res.json(msgStore.get(id) ?? []);
});

router.post("/anthropic/conversations/:id/messages", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const conv = convStore.get(id);
  if (!conv) { res.status(404).json({ error: "Conversation not found" }); return; }

  const { content } = req.body;
  const msgs = msgStore.get(id) ?? [];

  const userMsg: Message = {
    id: msgIdSeq++,
    conversationId: id,
    role: "user",
    content,
    createdAt: new Date().toISOString(),
  };
  msgs.push(userMsg);
  msgStore.set(id, msgs);

  const chatMessages = msgs.slice(0, -1).concat(userMsg).map((m) => ({
    role: m.role as "user" | "assistant",
    content: m.content,
  }));

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  let fullResponse = "";

  try {
    const stream = await openrouter.chat.completions.create({
      model: "meta-llama/llama-3.3-70b-instruct:free",
      max_tokens: 8192,
      stream: true,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        ...chatMessages,
      ],
    });

    for await (const chunk of stream) {
      const text = chunk.choices[0]?.delta?.content ?? "";
      if (text) {
        fullResponse += text;
        res.write(`data: ${JSON.stringify({ content: text })}\n\n`);
      }
    }
  } catch (err) {
    const fallback = "AI analysis unavailable. Please check your OpenRouter integration.";
    fullResponse = fallback;
    res.write(`data: ${JSON.stringify({ content: fallback })}\n\n`);
  }

  const assistantMsg: Message = {
    id: msgIdSeq++,
    conversationId: id,
    role: "assistant",
    content: fullResponse,
    createdAt: new Date().toISOString(),
  };
  msgs.push(assistantMsg);
  msgStore.set(id, msgs);

  res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
  res.end();
});

export default router;
