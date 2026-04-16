const MAX_BUFFER_LINES = 5000;
let wiresharkBuffer: string[] = [];
let browserBuffer: string[] = [];

export function appendLiveWiresharkBuffer(line: string) {
  wiresharkBuffer.push(line);
  if (wiresharkBuffer.length > MAX_BUFFER_LINES) {
    wiresharkBuffer = wiresharkBuffer.slice(-MAX_BUFFER_LINES);
  }
}

export function getLiveWiresharkBuffer(): string {
  return wiresharkBuffer.join("\n");
}

export function clearLiveWiresharkBuffer() {
  wiresharkBuffer = [];
}

export function getLiveWiresharkLines(): string[] {
  return [...wiresharkBuffer];
}

export function appendLiveBrowserBuffer(entries: string[]) {
  browserBuffer.push(...entries);
  if (browserBuffer.length > MAX_BUFFER_LINES) {
    browserBuffer = browserBuffer.slice(-MAX_BUFFER_LINES);
  }
}

export function getLiveBrowserBuffer(): string {
  return browserBuffer.join("\n");
}

export function clearLiveBrowserBuffer() {
  browserBuffer = [];
}
