import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';

@Entity('audits')
export class AuditEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text' })
  code: string;

  @Column({ nullable: true })
  contractName: string;

  @Column({ type: 'jsonb' })
  result: any;

  @Column()
  hash: string;

  @CreateDateColumn()
  createdAt: Date;

  @Column({ default: 'slither' })
  analyzer: string;
}
