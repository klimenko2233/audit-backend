import { Injectable, Logger } from '@nestjs/common';
import {
  AuditResult,
  Vulnerability,
} from './interfaces/audit-result.interface';
import { DeFiCheck, DeFiAuditResult } from './interfaces/defi-audit.interface';
import { SlitherService } from '../slither/slither.service';
import { SlitherRequestDto } from '../slither/dto/slither-request.dto';
import { AuditRepository } from './audit.repository';
import { SlitherVulnerability } from '../slither/interfaces/slither-vulnerability.interface';

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(
    private readonly slitherService: SlitherService,
    private readonly auditRepository: AuditRepository,
  ) {}

  async analyzeContract(
    code: string,
    contractName?: string,
    saveToDb: boolean = true,
  ): Promise<AuditResult> {
    const isSlitherHealthy = await this.slitherService.healthCheck();

    let result: AuditResult;

    if (isSlitherHealthy) {
      this.logger.log('Using Slither for advanced analysis');
      result = await this.analyzeWithSlither(code, contractName);
    } else {
      this.logger.warn('Slither unavailable, using basic analysis');
      result = this.basicAnalysis(code);
    }

    if (saveToDb) {
      try {
        await this.auditRepository.saveAuditResult(
          code,
          contractName,
          result,
          isSlitherHealthy ? 'slither' : 'basic',
        );
      } catch (error: unknown) {
        const errorMessage =
          error instanceof Error ? error.message : 'Unknown error';
        this.logger.error('Failed to save audit result:', errorMessage);
      }
    }

    return result;
  }

  async analyzeDeFiContract(
    code: string,
    contractName?: string,
  ): Promise<DeFiAuditResult> {
    const basicResult = await this.analyzeContract(code, contractName, false);

    const defiChecks = this.checkDeFiSpecific(code);

    const riskScore = this.calculateRiskScore(basicResult, defiChecks);

    const result: DeFiAuditResult = {
      ...basicResult,
      defiChecks,
      riskScore,
    };

    try {
      await this.auditRepository.saveAuditResult(
        code,
        contractName,
        result,
        'slither+defi',
      );
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      this.logger.error('Failed to save DeFi audit result:', errorMessage);
    }

    return result;
  }

  private async analyzeWithSlither(
    code: string,
    contractName?: string,
  ): Promise<AuditResult> {
    const requestDto: SlitherRequestDto = {
      code,
      contract_name: contractName || 'Contract',
    };

    try {
      const slitherResult =
        await this.slitherService.analyzeWithSlither(requestDto);

      if (!slitherResult.compilation_successful) {
        const errorMessage = slitherResult.error || 'Unknown compilation error';
        this.logger.warn(`Compilation failed: ${errorMessage}`);
        return this.basicAnalysis(code);
      }

      const vulnerabilities: Vulnerability[] = [];

      for (const slitherVuln of slitherResult.vulnerabilities) {
        if (this.isFalsePositive(slitherVuln, code)) {
          continue;
        }

        const vulnerability = this.convertSlitherVulnerability(
          slitherVuln,
          code,
        );
        if (vulnerability) {
          vulnerabilities.push(vulnerability);
        }
      }

      const basicResult = this.basicAnalysis(code);
      const mergedVulnerabilities = this.mergeVulnerabilities(
        vulnerabilities,
        basicResult.vulnerabilities,
      );

      const summary = this.calculateSummary(mergedVulnerabilities);

      this.logger.debug(`Analysis complete: ${summary.total} vulnerabilities`);

      return { vulnerabilities: mergedVulnerabilities, summary };
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error
          ? error.message
          : 'Unknown error during Slither analysis';
      this.logger.error(`Slither analysis failed: ${errorMessage}`);
      return this.basicAnalysis(code);
    }
  }

  private isFalsePositive(
    slitherVuln: SlitherVulnerability,
    code: string,
  ): boolean {
    const check = slitherVuln.check;
    const lines = slitherVuln.lines;
    const codeLines = code.split('\n');

    if (check === 'reentrancy' && lines.length > 0) {
      const lineNumber = lines[0] - 1;
      if (lineNumber >= 0 && lineNumber < codeLines.length) {
        const line = codeLines[lineNumber];
        if (line.includes('.transfer(')) {
          this.logger.debug(
            `Filtering false positive reentrancy for transfer() on line ${lines[0]}`,
          );
          return true;
        }
      }
    }

    return false;
  }

  private convertSlitherVulnerability(
    slitherVuln: SlitherVulnerability,
    code: string,
  ): Vulnerability | null {
    const check = slitherVuln.check;
    const impact = slitherVuln.impact;
    const description = slitherVuln.description;
    const lines = slitherVuln.lines;

    const typeMapping: Record<string, string> = {
      reentrancy: 'REENTRANCY',
      'reentrancy-eth': 'REENTRANCY',
      'reentrancy-no-eth': 'REENTRANCY',
      'tx-origin': 'TX_ORIGIN',
      'unchecked-lowlevel': 'UNCHECKED_CALL',
      'unchecked-send': 'UNCHECKED_CALL',
      'uninitialized-state': 'UNINITIALIZED_STORAGE',
      'uninitialized-storage': 'UNINITIALIZED_STORAGE',
      'arbitrary-send': 'ARBITRARY_SEND',
      'weak-prng': 'WEAK_RANDOMNESS',
      delegatecall: 'DELEGATECALL',
      'unbounded-iteration': 'UNBOUNDED_LOOP',
    };

    const type = typeMapping[check] || check.toUpperCase().replace(/-/g, '_');
    const severity = this.mapImpactToSeverity(impact);
    const line = lines.length > 0 ? lines[0] : 1;
    const recommendation = this.getRecommendation(check);

    let detailedDescription = description;
    if (lines.length > 0) {
      const lineNumber = lines[0] - 1;
      if (lineNumber >= 0 && lineNumber < code.split('\n').length) {
        const codeLine = code.split('\n')[lineNumber];
        if (codeLine.includes('.call{value:')) {
          detailedDescription =
            'Unprotected external call with value transfer. Attacker can re-enter contract.';
        } else if (codeLine.includes('tx.origin')) {
          detailedDescription =
            'Using tx.origin for authentication makes contract vulnerable to phishing attacks.';
        }
      }
    }

    return {
      type,
      severity,
      line,
      description: detailedDescription,
      recommendation,
    };
  }

  private mergeVulnerabilities(
    slitherVulnerabilities: Vulnerability[],
    basicVulnerabilities: Vulnerability[],
  ): Vulnerability[] {
    const merged: Vulnerability[] = [...slitherVulnerabilities];

    for (const basicVuln of basicVulnerabilities) {
      const isDuplicate = slitherVulnerabilities.some(
        (slitherVuln) =>
          slitherVuln.type === basicVuln.type &&
          Math.abs(slitherVuln.line - basicVuln.line) <= 2,
      );

      if (!isDuplicate) {
        merged.push(basicVuln);
      }
    }

    return merged.sort((a, b) => a.line - b.line);
  }

  private mapImpactToSeverity(
    impact: string,
  ): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const impactMap: Record<string, 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'> = {
      High: 'HIGH',
      Medium: 'MEDIUM',
      Low: 'LOW',
      Informational: 'LOW',
    };

    return impactMap[impact] || 'MEDIUM';
  }

  private getRecommendation(check: string): string {
    const recommendations: Record<string, string> = {
      reentrancy:
        'Use ReentrancyGuard from OpenZeppelin or implement Checks-Effects-Interactions pattern. For transfers, consider using transfer() which limits gas.',
      'reentrancy-eth':
        'Use ReentrancyGuard when transferring ETH. Update state before making external calls.',
      'reentrancy-no-eth':
        'Use nonReentrant modifier for functions that make external calls.',
      'tx-origin':
        'Replace tx.origin with msg.sender. tx.origin can be spoofed by intermediate contracts.',
      'unchecked-lowlevel':
        'Always check the return value of low-level calls: require(success, "Call failed").',
      'unchecked-send':
        'Check the return value of send() calls or use transfer() which reverts on failure.',
      'uninitialized-state':
        'Initialize all state variables in constructor or declaration.',
      'uninitialized-storage':
        'Explicitly initialize storage pointers to avoid unexpected behavior.',
      'arbitrary-send':
        'Implement access controls and validate recipient addresses.',
      'weak-prng':
        'Use Chainlink VRF or commit-reveal scheme for secure randomness.',
      delegatecall:
        "Validate the target contract and be aware that it executes in caller's context.",
      'unbounded-iteration':
        'Limit loop iterations or use pagination for large arrays.',
      'shadowing-state':
        'Avoid naming local variables the same as state variables.',
      suicidal: 'Implement timelock or multi-sig for selfdestruct functions.',
    };

    return (
      recommendations[check] ||
      'Review security best practices and consider an external audit.'
    );
  }

  private calculateSummary(
    vulnerabilities: Vulnerability[],
  ): AuditResult['summary'] {
    return {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter((v) => v.severity === 'CRITICAL').length,
      high: vulnerabilities.filter((v) => v.severity === 'HIGH').length,
      medium: vulnerabilities.filter((v) => v.severity === 'MEDIUM').length,
      low: vulnerabilities.filter((v) => v.severity === 'LOW').length,
    };
  }

  private basicAnalysis(code: string): AuditResult {
    if (!code || typeof code !== 'string') {
      throw new Error('Incorrect contract code');
    }

    const vulnerabilities: Vulnerability[] = [];
    const lines = code.split('\n');

    this.logger.debug(`Basic analysis: ${lines.length} lines`);

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
            'Replace "function constructor() public" with "constructor()"',
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

    this.logger.debug(
      `Basic analysis complete: ${summary.total} vulnerabilities`,
    );
    return { vulnerabilities, summary };
  }

  private checkDeFiSpecific(code: string): DeFiCheck[] {
    const checks: DeFiCheck[] = [];
    const lowerCode = code.toLowerCase();

    if (lowerCode.includes('flashloan') || lowerCode.includes('flash loan')) {
      checks.push({
        type: 'FLASH_LOAN_RISK',
        severity: 'HIGH',
        description:
          'Контракт имеет функциональность flash loan без надлежащих защитных механизмов',
        recommendation:
          'Реализуйте проверки ценовых оракулов, временные блокировки (timelocks) и ограничения по сумме',
      });
    }

    if (
      lowerCode.includes('oracle') ||
      lowerCode.includes('getprice') ||
      lowerCode.includes('pricefeed') ||
      lowerCode.includes('chainlink')
    ) {
      checks.push({
        type: 'ORACLE_MANIPULATION',
        severity: 'MEDIUM',
        description:
          'Контракт использует ценовые оракулы без механизмов защиты от манипуляций',
        recommendation:
          'Используйте несколько оракулов, реализуйте circuit breakers и временные задержки',
      });
    }

    if (
      lowerCode.includes('frontrun') ||
      lowerCode.includes('sandwich') ||
      lowerCode.includes('arbitrage') ||
      lowerCode.includes('swap')
    ) {
      checks.push({
        type: 'MEV_RISK',
        severity: 'MEDIUM',
        description:
          'Контракт подвержен рискам максимально извлекаемой стоимости (MEV)',
        recommendation:
          'Используйте commit-reveal схемы, Flashbots или приватные транзакции',
      });
    }

    if (
      lowerCode.includes('liquidity') ||
      lowerCode.includes('pool') ||
      lowerCode.includes('amm') ||
      lowerCode.includes('uniswap')
    ) {
      checks.push({
        type: 'LIQUIDITY_RISK',
        severity: 'HIGH',
        description:
          'Контракт зависит от ликвидности пулов и может быть подвержен атакам',
        recommendation:
          'Реализуйте механизмы защиты от истощения ликвидности и slippage control',
      });
    }

    if (
      lowerCode.includes('collateral') ||
      lowerCode.includes('debt') ||
      lowerCode.includes('loan') ||
      lowerCode.includes('borrow')
    ) {
      checks.push({
        type: 'COLLATERAL_RISK',
        severity: 'HIGH',
        description:
          'Контракт использует залоговое обеспечение без механизмов защиты от волатильности',
        recommendation:
          'Реализуйте динамические коэффициенты LTV, аукционы ликвидации и оракулы цен',
      });
    }

    if (
      lowerCode.includes('bridge') ||
      lowerCode.includes('crosschain') ||
      lowerCode.includes('multichain') ||
      lowerCode.includes('wormhole')
    ) {
      checks.push({
        type: 'BRIDGE_RISK',
        severity: 'CRITICAL',
        description:
          'Контракт взаимодействует с кросс-чейн мостами, которые часто взламывают',
        recommendation:
          'Используйте только проверенные мосты, реализуйте лимиты и временные блокировки',
      });
    }

    if (
      lowerCode.includes('governance') ||
      lowerCode.includes('vote') ||
      lowerCode.includes('dao') ||
      lowerCode.includes('proposal')
    ) {
      checks.push({
        type: 'GOVERNANCE_RISK',
        severity: 'MEDIUM',
        description:
          'Контракт имеет механизмы управления, которые могут быть захвачены',
        recommendation:
          'Реализуйте временные блокировки для голосования, кворумы и защиту от whale attacks',
      });
    }

    return checks;
  }

  private calculateRiskScore(
    auditResult: AuditResult,
    defiChecks: DeFiCheck[],
  ): number {
    let score = 0;

    const vulnerabilityWeights: Record<string, number> = {
      CRITICAL: 25,
      HIGH: 15,
      MEDIUM: 8,
      LOW: 3,
    };

    const defiCheckWeights: Record<string, number> = {
      CRITICAL: 30,
      HIGH: 20,
      MEDIUM: 10,
      LOW: 5,
    };

    for (const vulnerability of auditResult.vulnerabilities) {
      score += vulnerabilityWeights[vulnerability.severity] || 0;
    }

    for (const check of defiChecks) {
      score += defiCheckWeights[check.severity] || 0;
    }

    return Math.min(score, 100);
  }
}
