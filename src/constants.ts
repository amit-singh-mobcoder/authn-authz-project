import dotenv from 'dotenv';
dotenv.config();

export class ConstantHelper {
    public static uri: string | undefined = process.env.MONGODB_URI;
    public static DB_NAME: string = 'auth-project';
    public static port: number = Number(process.env.PORT) | 4000;
    public static jwtSecretKey: string = String(process.env.JWT_SECRET_KEY); 
}