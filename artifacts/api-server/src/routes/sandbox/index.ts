import { Router } from "express";

const router = Router();

function generateSandboxData() {
  const syscallNames = [
    "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile",
    "NtCreateProcess", "NtTerminateProcess", "NtAllocateVirtualMemory",
    "NtCreateSection", "NtMapViewOfSection", "NtCreateMutant",
    "NtCreateKey", "NtSetValueKey", "NtDeleteKey",
    "NtConnect", "NtSendMessage", "NtQuerySystemInformation",
    "NtSetInformationThread", "NtCreateThread", "NtResumeThread",
    "LdrLoadDll", "NtQueryVirtualMemory", "NtProtectVirtualMemory",
  ];

  const syscallCategories: Record<string, string> = {
    "NtCreateFile": "file", "NtOpenFile": "file", "NtReadFile": "file", "NtWriteFile": "file",
    "NtCreateProcess": "process", "NtTerminateProcess": "process",
    "NtAllocateVirtualMemory": "memory", "NtCreateSection": "memory", "NtMapViewOfSection": "memory", "NtProtectVirtualMemory": "memory", "NtQueryVirtualMemory": "memory",
    "NtCreateMutant": "sync",
    "NtCreateKey": "registry", "NtSetValueKey": "registry", "NtDeleteKey": "registry",
    "NtConnect": "network", "NtSendMessage": "network",
    "NtQuerySystemInformation": "system", "NtSetInformationThread": "system",
    "NtCreateThread": "thread", "NtResumeThread": "thread",
    "LdrLoadDll": "dll",
  };

  const syscalls = syscallNames.map((name, i) => ({
    id: i + 1,
    name,
    category: syscallCategories[name] || "other",
    count: Math.floor(Math.random() * 500) + 10,
    timestamp: Date.now() - (syscallNames.length - i) * 1200,
  }));

  const protocols = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SMB", "FTP"];
  const maliciousIps = ["185.220.101.45", "91.108.4.12", "45.142.212.100", "193.188.23.44"];
  const benignIps = ["8.8.8.8", "1.1.1.1", "172.217.3.100", "13.107.42.14"];

  const networkActivity = Array.from({ length: 18 }, (_, i) => {
    const malicious = Math.random() > 0.6;
    return {
      id: i + 1,
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      srcIp: "10.0.0." + (Math.floor(Math.random() * 50) + 1),
      dstIp: malicious
        ? maliciousIps[Math.floor(Math.random() * maliciousIps.length)]
        : benignIps[Math.floor(Math.random() * benignIps.length)],
      dstPort: malicious
        ? [4444, 1337, 6667, 8080, 31337][Math.floor(Math.random() * 5)]
        : [80, 443, 53, 25, 587][Math.floor(Math.random() * 5)],
      bytes: Math.floor(Math.random() * 65000) + 100,
      timestamp: Date.now() - i * 3000,
      malicious,
    };
  });

  const processTree = [
    { pid: 1248, name: "explorer.exe", parentPid: 624, cmdLine: "C:\\Windows\\explorer.exe", suspicious: false },
    { pid: 3892, name: "malware.exe", parentPid: 1248, cmdLine: "C:\\Temp\\malware.exe --silent", suspicious: true },
    { pid: 4012, name: "cmd.exe", parentPid: 3892, cmdLine: "cmd.exe /c net user hacker P@ss123 /add", suspicious: true },
    { pid: 4156, name: "net.exe", parentPid: 4012, cmdLine: "net user hacker P@ss123 /add", suspicious: true },
    { pid: 4201, name: "powershell.exe", parentPid: 3892, cmdLine: "powershell.exe -enc JABz...", suspicious: true },
    { pid: 4320, name: "svchost.exe", parentPid: 3892, cmdLine: "svchost.exe -k netsvcs", suspicious: true },
    { pid: 624, name: "winlogon.exe", parentPid: 4, cmdLine: "winlogon.exe", suspicious: false },
  ];

  return {
    sampleId: "SAMPLE-" + Math.random().toString(36).slice(2, 8).toUpperCase(),
    status: "running",
    systemCalls: syscalls,
    networkActivity,
    processTree,
    totalSyscalls: syscalls.reduce((s, c) => s + c.count, 0),
    totalNetworkConnections: networkActivity.length,
    runningTime: 120 + Math.random() * 60,
  };
}

router.get("/sandbox/events", (_req, res) => {
  res.json(generateSandboxData());
});

export default router;
