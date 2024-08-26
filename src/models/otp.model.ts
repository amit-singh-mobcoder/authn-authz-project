import mongoose, { model } from "mongoose";

export interface IOtp extends Document {
    email: string;
    otp: string;
}

const otpSchema = new mongoose.Schema(
    {
        email:{
            type: String,
            required: true,
            unique: true,
        },
        otp: {
            type: String,
            required: true
        }
    }
);

export const OtpModel = model<IOtp>('OtpModel', otpSchema);