import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditEntity } from './entities/audit.entity';
import { AuditResult } from './interfaces/audit-result.interface';
import * as crypto from 'crypto';

@Injectable()
export class AuditRepository {
  constructor(
    @InjectRepository(AuditEntity)
    private readonly repository: Repository<AuditEntity>,
  ) {}

  async saveAuditResult(
    code: string,
    contractName: string | undefined,
    result: AuditResult,
    analyzer: string = 'slither',
  ): Promise<AuditEntity> {
    const hash = crypto.createHash('sha256').update(code).digest('hex');

    const audit = this.repository.create({
      code,
      contractName,
      result,
      hash,
      analyzer,
    });

    return await this.repository.save(audit);
  }

  async findAuditByHash(hash: string): Promise<AuditEntity | null> {
    return await this.repository.findOne({
      where: { hash },
      order: { createdAt: 'DESC' },
    });
  }

  async getAuditHistory(
    page: number = 1,
    limit: number = 10,
  ): Promise<{ audits: AuditEntity[]; total: number }> {
    const skip = (page - 1) * limit;

    const [audits, total] = await this.repository.findAndCount({
      skip,
      take: limit,
      order: { createdAt: 'DESC' },
    });

    return { audits, total };
  }

  async findOne(id: string): Promise<AuditEntity | null> {
    return await this.repository.findOne({ where: { id } });
  }
}
