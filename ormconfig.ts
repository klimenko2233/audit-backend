import { DataSource } from 'typeorm';
import { AuditEntity } from './src/audit/entities/audit.entity';

export const createDataSource = () => {
  return new DataSource({
    type: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432'),
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_DATABASE || 'audit_service',
    entities: [AuditEntity],
    migrations: ['src/migrations/*.ts'],
    synchronize: process.env.NODE_ENV === 'development',
  });
};

const dataSource = createDataSource();
export default dataSource;
