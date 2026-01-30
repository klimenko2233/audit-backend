import {
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class AuditContractDto {
  @IsString({ message: 'Code must be a string' })
  @IsNotEmpty({ message: 'Code cannot be empty' })
  @MinLength(10, { message: 'Code must be at least 10 characters long' })
  @MaxLength(50000, { message: 'Code cannot be longer than 50000 characters' })
  code: string;

  @IsOptional()
  @IsString()
  contractName?: string;
}
