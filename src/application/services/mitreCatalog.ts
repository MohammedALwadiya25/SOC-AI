import type { MitreTechnique } from "../../domain/models.js";

export const MITRE_CATALOG: MitreTechnique[] = [
  {
    id: "T1110",
    name: "Brute Force",
    tactic: "Credential Access",
    description: "Adversaries may use brute force techniques to gain access to accounts.",
    url: "https://attack.mitre.org/techniques/T1110/",
  },
  {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "Execution",
    description: "Adversaries may abuse command and script interpreters to execute commands.",
    url: "https://attack.mitre.org/techniques/T1059/",
  },
  {
    id: "T1046",
    name: "Network Service Discovery",
    tactic: "Discovery",
    description: "Adversaries may attempt to discover services running on remote hosts.",
    url: "https://attack.mitre.org/techniques/T1046/",
  },
  {
    id: "T1071",
    name: "Application Layer Protocol",
    tactic: "Command and Control",
    description: "Adversaries may communicate using application layer protocols.",
    url: "https://attack.mitre.org/techniques/T1071/",
  },
  {
    id: "T1566",
    name: "Phishing",
    tactic: "Initial Access",
    description: "Adversaries may send phishing messages to gain access.",
    url: "https://attack.mitre.org/techniques/T1566/",
  },
  {
    id: "T1021",
    name: "Remote Services",
    tactic: "Lateral Movement",
    description: "Adversaries may use valid accounts to log into remote services.",
    url: "https://attack.mitre.org/techniques/T1021/",
  },
  {
    id: "T1041",
    name: "Exfiltration Over C2 Channel",
    tactic: "Exfiltration",
    description: "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
    url: "https://attack.mitre.org/techniques/T1041/",
  },
  {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Defense Evasion",
    description: "Adversaries may obtain and abuse credentials of existing accounts.",
    url: "https://attack.mitre.org/techniques/T1078/",
  },
  {
    id: "T1499",
    name: "Endpoint Denial of Service",
    tactic: "Impact",
    description: "Adversaries may perform endpoint denial of service attacks.",
    url: "https://attack.mitre.org/techniques/T1499/",
  },
  {
    id: "T1090",
    name: "Proxy",
    tactic: "Command and Control",
    description: "Adversaries may use a connection proxy to direct network traffic.",
    url: "https://attack.mitre.org/techniques/T1090/",
  },
];

export function getTechniqueById(id: string): MitreTechnique | undefined {
  return MITRE_CATALOG.find((technique) => technique.id === id);
}
