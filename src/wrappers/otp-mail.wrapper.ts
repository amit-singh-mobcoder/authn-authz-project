import nodemailer from 'nodemailer';
import { ConstantHelper } from '../constants';

export class OtpMailer {
    private otp: string;
    private receiverEmail: string;
    private userMail: string = ConstantHelper.MAIL_USER;
    private userPass: string = ConstantHelper.MAIL_PASS;

    constructor(otp: string, receiverEmail: string) {
        if (!otp) {
            throw new Error('OTP is required');
        }
        if (!receiverEmail) {
            throw new Error('Receiver Email is required');
        }
        this.otp = otp;
        this.receiverEmail = receiverEmail;
    }

    private createTransporter() {
        return nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: this.userMail,
                pass: this.userPass,
            }
        });
    }

    private createMailOptions() {
        return {
            from: this.userMail,
            to: this.receiverEmail,
            subject: 'OTP for password reset',
            html: `
                <div>
                    <h2>Security Code</h2>
                    <p>Please use the following security code for the account ${this.receiverEmail}.</p>
                    <p>Security code: <b>${this.otp}</b></p>
                    <p>code is only valid for 5 minute.</p>
                </div>
            `,
        };
    }

    public async send() {
        const transporter = this.createTransporter();
        const mailOptions = this.createMailOptions();

        try {
            await transporter.sendMail(mailOptions);
            console.log('OTP email sent successfully');
        } catch (error) {
            console.error('Failed to send OTP email:', error);
            throw new Error('Failed to send OTP email');
        }
    }
    
    public static create(otp: string, receiverEmail: string): OtpMailer {
        return new OtpMailer(otp, receiverEmail);
    }
}
