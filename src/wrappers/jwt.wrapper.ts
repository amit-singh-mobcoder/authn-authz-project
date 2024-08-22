import jwt, { Secret, SignOptions, VerifyOptions } from 'jsonwebtoken'

export class JwtWrapper {
    public static sign(payload: string|Buffer|object, secretOrPrivateKey: Secret, options?: SignOptions): string{
        return jwt.sign(payload, secretOrPrivateKey, options);
    }

    public static verify(token: string, secretOrPublicKey: Secret, options?: VerifyOptions): object | string {
        return jwt.verify(token, secretOrPublicKey, options);
    }
}