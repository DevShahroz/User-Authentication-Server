import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService
    ) { }

    async signUp(email: string, pass: string, name: string): Promise<any> {
        const userExists = await this.usersService.findOne(email);
        if (userExists) {
            throw new ConflictException('User already exists');
        }

        const hashedPassword = await bcrypt.hash(pass, 10);
        const user = await this.usersService.create({
            email,
            password: hashedPassword,
            name,
        });

        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { password, ...result } = user;
        return result;
    }

    async signIn(email: string, pass: string): Promise<any> {
        const user = await this.usersService.findOne(email);
        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const isMatch = await bcrypt.compare(pass, user.password);
        if (!isMatch) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const payload = { sub: user.email, email: user.email, name: user.name };
        return {
            access_token: await this.jwtService.signAsync(payload),
            user: {
                email: user.email,
                name: user.name
            }
        };
    }
}
