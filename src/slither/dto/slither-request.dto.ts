import { IsString, IsNotEmpty, MaxLength, IsOptional } from 'class-validator';

export class SlitherRequestDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(100000)
  code: string;

  @IsOptional()
  @IsString()
  contract_name?: string = 'Contract';
}
