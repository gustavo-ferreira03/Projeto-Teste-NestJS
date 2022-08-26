import { Body, Controller, Post } from "@nestjs/common";
import { ApiBody, ApiCreatedResponse, ApiOkResponse, ApiUnauthorizedResponse } from "@nestjs/swagger";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthService } from "./auth.service";
import { AuthDto } from "./dto";

@Controller()
export class AuthController {
    constructor(private prisma: PrismaService, private authService: AuthService){}

    @Post('login')
    @ApiCreatedResponse({ description: 'User login' })
    @ApiUnauthorizedResponse({ description: 'Invalid credentials' })
    @ApiBody({ type: AuthDto })
    login(@Body() dto: AuthDto) {
        return this.authService.login(dto)
    }

    @Post('signup')
    @ApiOkResponse({ description: 'User registration' })
    @ApiBody({ type: AuthDto })
    signup(@Body() dto: AuthDto) {
        return this.authService.signup(dto)
    }
}