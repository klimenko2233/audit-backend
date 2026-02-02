import { AuditResult } from './audit-result.interface';

export interface DeFiCheck {
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  recommendation: string;
}

export interface DeFiAuditResult extends AuditResult {
  defiChecks: DeFiCheck[];
  riskScore: number;
}
