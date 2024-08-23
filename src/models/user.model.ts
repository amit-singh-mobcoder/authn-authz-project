import mongoose, {Document, Schema, model} from "mongoose";

export interface IUser extends Document {
    name: {
        firstName: string,
        lastName: string
    };
    username: string;
    email: string;
    password: string;
    role: string;
}

const userSchema = new Schema(
    {
        name: {
            type: Object as () => {firstName: string, lastName: string},
            required: true
            
        },
        username: { 
            type: String,
            required: true,
            index: true,
            unique: true
        },
        email: {
            type: String,
            required: true,
            unique: true
        },
        password: {
            type: String,
            required: true,
        },
        role: {
            type: String,
            enum: ['admin', 'user'],
            default: 'user'
        }
    },
    {timestamps: true}
)

export const UserModel = model<IUser>('UserModel', userSchema);