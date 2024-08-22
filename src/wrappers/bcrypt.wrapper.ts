import bcrypt from 'bcryptjs'

export class BcryptWrapper {
    public static hash(data: string, saltOrRound: number | string = 10 ): Promise<string> {
        return bcrypt.hash(data, saltOrRound);
    }
    
    public static compare(data: string, encrypted: string): Promise<boolean> {
        return bcrypt.compare(data, encrypted);
    }
}