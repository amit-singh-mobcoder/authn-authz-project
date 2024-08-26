import otpGenerator from 'otp-generator';

export class OtpWrapper {
    public static generate() : string {
        return otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false })
    }
    private OtpWrapper() {}
}