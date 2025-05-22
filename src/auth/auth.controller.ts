import { Body, Controller, Get, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response } from 'express';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }
  @Post('signup')
  async signup(@Body() body: { username: string; password: string }) {
    return this.authService.signup(body.username, body.password);
  }

  // 로그인
  @Post('login')
  async login(
    @Body() body: { userName: string; password: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.validateUser(
      body.userName,
      body.password,
    );
    if (!user) {
      return res.status(401).json({ message: '아이디 또는 비밀번호가 틀립니다.' });
    }

    const token = await this.authService.login(user);
    res.cookie('token', token, { httpOnly: true });
    return { message: '로그인 성공' };
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async profile(@Req() req: Request) {
    return req.user;
  }
}

