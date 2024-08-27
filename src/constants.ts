import dotenv from 'dotenv';
dotenv.config();

export abstract class ConstantHelper {
    public static uri: string | undefined = process.env.MONGODB_URI;
    public static DB_NAME: string = 'auth-project';
    public static port: number = Number(process.env.PORT) | 4000;
    public static jwtSecretKey: string = String(process.env.JWT_SECRET_KEY);
    public static mail_user: string = String(process.env.MAIL_USER);
    public static mail_pass: string = String(process.env.MAIL_PASS); 
}

interface IMongooseOptions {
    serverSelectionTimeoutMS: number,
    socketTimeoutMS: number,
}

export const mongooseOptions: IMongooseOptions = {
    serverSelectionTimeoutMS: 30000, // Adjust this as needed
    socketTimeoutMS: 30000, // Adjust this as needed
}