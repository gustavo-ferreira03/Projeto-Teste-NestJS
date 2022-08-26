import { ForbiddenException, Injectable } from "@nestjs/common";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaService } from "src/prisma/prisma.service";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService
    ) {}

    async login(dto: AuthDto) {
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        })
        if (!user) 
            throw new ForbiddenException('Credentials incorrect');

        const pwMatches = await argon.verify(dto.email, dto.password);

        if (!pwMatches)
            throw new ForbiddenException('Credentials incorrect');

        return user;

    }

    async signup(dto: AuthDto) {
        try{
            const hash = await argon.hash(dto.password);
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                }
            })
            return user;
        } catch(error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code == 'P2002') {
                    throw new ForbiddenException('Credentials taken')
                }
            }
        }
    }

    async signToken(
        userId: number,
        email: string,
    ) {
        const payload = {
            sub: userId,
            email
        }
        const secret = this.config.get('JWT_SECRET')

        return this.jwt.signAsync(payload, {
            expiresIn: '16m',
            secret: secret,
        })
    }
}