import http from "http";
import { WebSocketServer, WebSocket } from "ws";
import app from "./app";
import { logger } from "./lib/logger";
import { appendLiveWiresharkBuffer, clearLiveWiresharkBuffer } from "./lib/liveCapture";

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

const server = http.createServer(app);

const wss = new WebSocketServer({ server, path: "/api/live-capture/wireshark-ws" });

wss.on("connection", (ws: WebSocket, req) => {
  logger.info({ ip: req.socket.remoteAddress }, "Live Wireshark WebSocket connected");
  clearLiveWiresharkBuffer();

  ws.on("message", (data: Buffer | string) => {
    const line = data.toString("utf8");
    appendLiveWiresharkBuffer(line);
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: "data", line }));
      }
    });
  });

  ws.on("close", () => {
    logger.info("Live Wireshark WebSocket disconnected");
  });

  ws.send(JSON.stringify({ type: "connected", message: "AegisCore Live Capture ready. Pipe tshark output here." }));
});

server.listen(port, () => {
  logger.info({ port }, "Server listening");
});
