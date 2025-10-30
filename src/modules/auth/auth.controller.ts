import { Body, Controller, Post, Req } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBody, ApiResponse, ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength, IsOptional } from 'class-validator';
import { AuthService } from './auth.service';
import type { Request } from 'express';

class RegisterDto {
  @ApiProperty({ example: 'user@example.com', description: 'User email' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'strongPassword123', description: 'Plain text password' })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'STUDENT', description: 'Role: ADMIN | STUDENT | TEACHER', required: false })
  @IsOptional()
  role?: string;
}

class LoginDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'strongPassword123' })
  @IsString()
  password: string;
}

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  async register(@Body() body: RegisterDto, @Req() req: Request) {
    return this.authService.register(body?.email, body?.password, body?.role || 'STUDENT');
  }

  @Post('login')
  @ApiOperation({ summary: 'Authenticate user and return JWT' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({ status: 200, description: 'Login successful, returns access_token' })
  async login(@Body() body: LoginDto, @Req() req: Request) {
    return this.authService.login(body?.email, body?.password);
  }
}
