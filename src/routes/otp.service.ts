import OtpRepository from "../repositories/otp.repository";
import { OtpWrapper } from "../wrappers/otp.wrapper";

export default class OtpService {
    otpRepository: OtpRepository;

    constructor(otpRepository: OtpRepository){
        this.otpRepository = otpRepository;
    }

    async createOtp(email: string, otpExpirationTime: Date) {
        const otp = OtpWrapper.generate();
        return await this.otpRepository.create(email, otp, otpExpirationTime);
    }

    async existedOtpWithEmail(email: string){
        const otp = await this.otpRepository.findOtpByEmail(email);
        return otp;
    }
}