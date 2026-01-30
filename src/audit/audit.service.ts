import { Injectable, Logger } from '@nestjs/common';
import {
  AuditResult,
  Vulnerability,
} from './interfaces/audit-result.interface';

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  analyzeContract(code: string): AuditResult {
    if (!code || typeof code !== 'string') {
      throw new Error('Incorrect contract code');
    }

    const vulnerabilities: Vulnerability[] = [];
    const lines = code.split('\n');

    this.logger.debug(`Analyzing the contract: ${lines.length} lines`);

    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      const trimmedLine = line.trim();

      if (
        !trimmedLine ||
        trimmedLine.startsWith('//') ||
        trimmedLine.startsWith('*')
      ) {
        return;
      }

      if (
        line.includes('.call{value:') ||
        line.includes('.call.value') ||
        line.includes('.send(') ||
        line.includes('.transfer(')
      ) {
        if (
          !line.includes('nonReentrant') &&
          !line.includes('ReentrancyGuard')
        ) {
          vulnerabilities.push({
            type: 'REENTRANCY',
            severity: 'HIGH',
            line: lineNumber,
            description:
              'Calling .call{value:} or .transfer() without reentrancy protection',
            recommendation:
              'Use the Checks-Effects-Interactions pattern or OpenZeppelin ReentrancyGuard',
          });
        }
      }

      if (line.includes('tx.origin')) {
        vulnerabilities.push({
          type: 'TX_ORIGIN',
          severity: 'MEDIUM',
          line: lineNumber,
          description: 'Using tx.origin for authorization',
          recommendation: 'Replace tx.origin with msg.sender',
        });
      }

      if (
        (line.includes('+') ||
          line.includes('-') ||
          line.includes('*') ||
          line.includes('/')) &&
        !line.includes('SafeMath') &&
        (line.includes('uint') || line.includes('int')) &&
        !line.includes('//')
      ) {
        vulnerabilities.push({
          type: 'INTEGER_OVERFLOW',
          severity: 'HIGH',
          line: lineNumber,
          description: 'Arithmetic operation without overflow check',
          recommendation:
            'Use SafeMath from OpenZeppelin or built-in checked operations',
        });
      }

      if (
        (line.includes('for(') || line.includes('while(')) &&
        !line.includes('//') &&
        !line.includes('length') &&
        !line.includes('range') &&
        !line.includes('<=')
      ) {
        vulnerabilities.push({
          type: 'UNBOUNDED_LOOP',
          severity: 'MEDIUM',
          line: lineNumber,
          description: 'A loop without an explicit iteration limit',
          recommendation: 'Add a limit on the number of iterations',
        });
      }

      if (
        line.includes('function') &&
        line.includes('constructor') &&
        line.includes('public')
      ) {
        vulnerabilities.push({
          type: 'DEPRECATED_CONSTRUCTOR',
          severity: 'LOW',
          line: lineNumber,
          description: 'Using outdated constructor syntax',
          recommendation:
            'Replace “function constructor() public” with “constructor()”',
        });
      }
    });

    const summary = {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter((v) => v.severity === 'CRITICAL').length,
      high: vulnerabilities.filter((v) => v.severity === 'HIGH').length,
      medium: vulnerabilities.filter((v) => v.severity === 'MEDIUM').length,
      low: vulnerabilities.filter((v) => v.severity === 'LOW').length,
    };

    this.logger.debug(`Analysis complete: ${summary.total} vulnerabilities`);
    return { vulnerabilities, summary };
  }
}
