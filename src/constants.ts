import dotenv from 'dotenv';
dotenv.config();

export abstract class ConstantHelper {
    public static MOGOGO_URI: string | undefined = process.env.MONGODB_URI;
    public static DB_NAME: string = 'auth-project';
    public static APP_PORT: number = Number(process.env.PORT) | 4000;
    public static JWT_SECRET_KEY: string = String(process.env.JWT_SECRET_KEY);
    public static MAIL_USER: string = String(process.env.MAIL_USER);
    public static MAIL_PASS: string = String(process.env.MAIL_PASS); 
}

interface IMongooseOptions {
    serverSelectionTimeoutMS: number,
    socketTimeoutMS: number,
}

export const mongooseOptions: IMongooseOptions = {
    serverSelectionTimeoutMS: 30000,
    socketTimeoutMS: 30000,
}