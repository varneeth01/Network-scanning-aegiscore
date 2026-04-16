import { Router } from "express";
import {
  getLiveWiresharkBuffer,
  getLiveWiresharkLines,
  clearLiveWiresharkBuffer,
  appendLiveBrowserBuffer,
  getLiveBrowserBuffer,
  clearLiveBrowserBuffer,
} from "../../lib/liveCapture";

const router = Router();

router.get("/live-capture/wireshark-buffer", (_req, res) => {
  res.json({
    data: getLiveWiresharkBuffer(),
    lineCount: getLiveWiresharkLines().length,
    ready: getLiveWiresharkLines().length > 0,
  });
});

router.delete("/live-capture/wireshark-buffer", (_req, res) => {
  clearLiveWiresharkBuffer();
  res.json({ cleared: true });
});

router.post("/live-capture/browser", (req, res) => {
  const { entries } = req.body as { entries?: string[] };
  if (!Array.isArray(entries)) {
    res.status(400).json({ error: "entries must be an array of strings" });
    return;
  }
  appendLiveBrowserBuffer(entries);
  res.json({ appended: entries.length, total: getLiveBrowserBuffer().split("\n").length });
});

router.get("/live-capture/browser-buffer", (_req, res) => {
  const data = getLiveBrowserBuffer();
  res.json({
    data,
    lineCount: data ? data.split("\n").filter(Boolean).length : 0,
    ready: data.length > 0,
  });
});

router.delete("/live-capture/browser-buffer", (_req, res) => {
  clearLiveBrowserBuffer();
  res.json({ cleared: true });
});

export default router;
