import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Prisma, users_role } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async register(email: string, password: string, role?: string) {
    // validate inputs to avoid passing undefined to bcrypt/prisma
    if (!email || !password) {
      throw new BadRequestException('Email and password are required');
    }
    if (typeof password !== 'string' || password.length < 6) {
      throw new BadRequestException('Password must be a string with at least 6 characters');
    }

    const existingUser = await this.prisma.users.findUnique({ where: { email } });
    if (existingUser) {
      throw new BadRequestException('Email already registered');
    }

    // pastikan role sesuai enum di database (uppercase)
    const allowedRoles = ['ADMIN', 'STUDENT', 'TEACHER'];
    const normalizedRole = (role || 'STUDENT').toUpperCase();

    if (!allowedRoles.includes(normalizedRole)) {
      throw new BadRequestException(`Invalid role. Allowed: ${allowedRoles.join(', ')}`);
    }
    const hashed = await bcrypt.hash(password, 10);
    const user = await this.prisma.users.create({
      data: { id: uuidv4(), email, password: hashed, role: normalizedRole as users_role, updatedAt: new Date() },
    });
    return { message: 'User registered', user };
  }

  async login(email: string, password: string) {
    // validate inputs to avoid calling Prisma with undefined values
    if (!email || !password) {
      throw new BadRequestException('Email and password are required');
    }

    const user = await this.prisma.users.findUnique({ where: { email } });
    if (!user) throw new UnauthorizedException('User not found');

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) throw new UnauthorizedException('Invalid credentials');

    const token = await this.jwt.signAsync({
      sub: user.id,
      email: user.email,
      role: user.role,
    });

    return { message: 'Login success', access_token: token };
  }
}
