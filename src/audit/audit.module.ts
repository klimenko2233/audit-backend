import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuditController } from './audit.controller';
import { AuditService } from './audit.service';
import { SlitherModule } from '../slither/slither.module';
import { AuditEntity } from './entities/audit.entity';
import { AuditRepository } from './audit.repository';

@Module({
  imports: [TypeOrmModule.forFeature([AuditEntity]), SlitherModule],
  controllers: [AuditController],
  providers: [AuditService, AuditRepository],
  exports: [AuditService],
})
export class AuditModule {}
