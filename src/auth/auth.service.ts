import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

export interface User {
  id: number;
  userName: string;
  password: string;
}

@Injectable()
export class AuthService {
  /* 인메모리 사용자 배열 */
  private users: User[] = []

  constructor(
    private configService: ConfigService,
    private readonly jwtService: JwtService
  ) { }

  async signup(userName: string, password: string) {
    const exists = this.users.find(u => u.userName === userName)
    if (exists) {
      throw new Error("이미 존재하는 아이디입니다.")
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user: User = {
      id: this.users.length + 1,
      userName: userName,
      password: hashedPassword
    }
    this.users.push(user)
    return { message: '회원가입 완료' }
  }

  async validateUser(userName: string, password: string) {
    const user = this.users.find(u => u.userName === userName)
    if (!user) return null;

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return null;
    return user;
  }

  async login(user: User) {
    const payload = { sub: user.id, userName: user.userName };
    const token = this.jwtService.sign(payload, {secret: this.configService.get<string>('JWT_SECRET')});
    return token;
  }
  findUserById(id: number) {
    console.log(id, this.users)
    return this.users.find(u => u.id === id);
  }
}
