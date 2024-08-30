import { IOtp, OtpModel } from "../models/otp.model";

export default class OtpRepository {

    async create(email: string, otp: string, otpExpirationTime: number): Promise<IOtp>{
        const otpDocument = new OtpModel({email, otp, otpExpiration: otpExpirationTime});
        return await otpDocument.save();
    }

    async findOtpByEmail(email: string){
        const otpDocument = await OtpModel.findOne({email});
        return otpDocument;
    }
    
    async deleteOtpByEmail(email: string){
        return await OtpModel.deleteOne({email})
    }
}