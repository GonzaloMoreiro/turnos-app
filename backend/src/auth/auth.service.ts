import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: registerDto.email },
    });
    if (existingUser) throw new Error('Email ya registrado');
    const hashedPassword = await bcrypt.hash(registerDto.password, 10);
    const user = await this.prisma.user.create({
      data: {
        email: registerDto.email,
        password: hashedPassword,
        role: registerDto.role,
      },
    });
    const { password, ...result } = user;
    return result;
  }

  async login(loginDto: LoginDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: loginDto.email },
    });
    if (!existingUser) throw new Error('Usuario no encontrado');
    const passValid = await bcrypt.compare(
      loginDto.password,
      existingUser.password,
    );
    if (!passValid) throw new Error('Credenciales invalidas');

    return {
      acces_token: this.jwtService.sign({
        sub: existingUser.id,
        email: existingUser.email,
        role: existingUser.role,
      }),
    };
  }
}
