import { createAgentSecurityReport, scanForAgent, type AgentSecurityReport } from '../../dist/agent.js';

const empty: AgentSecurityReport = createAgentSecurityReport([], '.');
const version: string = empty.tool.version;
const status: 'pass' | 'fail' = empty.status;

void version;
void status;
void scanForAgent;
