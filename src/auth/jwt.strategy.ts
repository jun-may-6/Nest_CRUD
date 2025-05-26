import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Request } from "express";
import { ExtractJwt, Strategy } from "passport-jwt";
import { AuthService } from "./auth.service";
import { ConfigService } from "@nestjs/config";


@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy){
  constructor(
    private configService: ConfigService,
    private authService: AuthService){
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => {
          console.log(req?.cookies?.token)
          return req?.cookies?.token
        },
      ]),
      secretOrKey: configService.get<string>('JWT_SECRET')!
    })
  }
  async validate(payload: any) {
    console.log("start validate")
    return this.authService.findUserById(payload.sub);
  }
}