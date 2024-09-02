import { IUser } from "../models/user.model";
import UserRepository from "../repositories/user.repository";
import { ApiError } from "../utils/ApiError";
import { BcryptWrapper } from "../wrappers/bcrypt.wrapper";
import { StatusHelper } from "../helpers/status.helper";
import { ConstantHelper } from "../constants";
import { JwtWrapper } from "../wrappers/jwt.wrapper";
import OtpRepository from "../repositories/otp.repository";
import { OtpWrapper } from "../wrappers/otp.wrapper";
import { OtpMailer } from "../wrappers/otp-mail.wrapper";
import { isValidObjectId, ObjectId } from "mongoose";

export default class UserService {
    userRepository: UserRepository;
    otpRepository: OtpRepository;

    constructor(userRepository: UserRepository, otpRepository: OtpRepository){
        this.userRepository = userRepository;
        this.otpRepository = otpRepository;
    }

    async registerUser(user: any): Promise<IUser> {
        const { firstName, lastName, username, email, password, role } = user;
    
        if (!firstName || !lastName || !username || !email || !password || !role) {
            throw new ApiError(StatusHelper.error400BadRequest, 'All fields are required');
        }
    
        const existingEmailUser = await this.userRepository.findUserByEmail(email);
        if (existingEmailUser) {
            throw new ApiError(StatusHelper.error409Conflict, 'User with this email already exists');
        }
    
        const existingUsernameUser = await this.userRepository.findUserByUsername(username);
        if (existingUsernameUser) {
            throw new ApiError(StatusHelper.error409Conflict, 'User with this username already exists');
        }
    
        const hashedPassword = await BcryptWrapper.hash(password);
    
        const newUser = await this.userRepository.addUser({
            name: { firstName, lastName },
            username,
            email,
            role,
            password: hashedPassword,
        });
    
        return newUser;
    }

    async loginUser(user: any){
        const {email, password} = user;

        if(!email || !password){
            throw new ApiError(StatusHelper.error400BadRequest, 'All fields are required, [email, password]');
        } 

        const existedUser = await this.userRepository.findUserByEmail(email);
        if(!existedUser){
            throw new ApiError(StatusHelper.error404NotFound, 'Invalid email, user with this email not found');
        }

        const isPasswordValid = await BcryptWrapper.compare(password, existedUser.password);
        if(!isPasswordValid){
            throw new ApiError(StatusHelper.error401Unauthorized, 'Invalid password');
        }

        const loggedInUser = await this.userRepository.findUserById(existedUser._id);

        const payload = {id : loggedInUser?._id}
        const secretKey = ConstantHelper.JWT_SECRET_KEY;
        const options = {expiresIn: '24h'}

        const token = JwtWrapper.sign(payload, secretKey, options);
        if(!token){
            throw new ApiError(StatusHelper.error400BadRequest, 'Something went wrong while generating jwt token');
        }

        const output = {
            name: `${loggedInUser?.name.firstName} ${loggedInUser?.name.lastName}`,
            token: token
        }
        return output;
    }
    
    async changePassword(user: any, requestBody: any){
        const loggedInUser = user;
        const {oldPassword, newPassword, confirmPassword} = requestBody;
        
        if(!oldPassword || !newPassword || !confirmPassword){
            throw new ApiError(StatusHelper.error400BadRequest, 'All fields are required, [ oldPassword, newPassword, confirmPassword ]');
        }

        if(newPassword !== confirmPassword){
            throw new ApiError(StatusHelper.error400BadRequest, 'newPassword and confirmPassword fields are different')
        }

        const currentUserDetails = await this.userRepository.findUserById(loggedInUser._id);

        const isPasswordValid = await BcryptWrapper.compare(oldPassword, String(currentUserDetails?.password))

        if(!isPasswordValid){
            throw new ApiError(StatusHelper.error401Unauthorized, 'Invalid old Password')
        }

        const hashed = await BcryptWrapper.hash(newPassword);

        const updatedUser = await this.userRepository.updateUserPasswordById(loggedInUser?._id, hashed)

        const output = {
            name: `${updatedUser?.name.firstName} ${updatedUser?.name.lastName}`,
            email: updatedUser?.email
        }

        return output;
    }

    async forgotPassword(email: string){
        if(!email){
            throw new ApiError(StatusHelper.error400BadRequest, 'Email is required')
        }

        const isUserExist = await this.userRepository.findUserByEmail(email);
        if(!isUserExist){
            throw new ApiError(StatusHelper.error404NotFound, 'User not found with this email')
        }

        // check is their any otp in the db with this email ?
        const existedOtp = await this.otpRepository.findOtpByEmail(isUserExist.email);

        // if existed, then delete it from the db
        if(existedOtp){
            try {
                await this.otpRepository.deleteOtpByEmail(email);
            } catch (error) {
                throw new ApiError(StatusHelper.error500InternalServerError, 'error while deleting the existed otp from db')
            }
        }

        // if there is no otp present in db, then generate it
        const otp = OtpWrapper.generate();

        // save this otp in the db and send email to the user
        await this.otpRepository.create(email, otp, Date.now() + 300000) // otp is only valid for 5 min = 300000 millisecond
        // sending mail
        const otpMail = OtpMailer.create(otp, email)
        await otpMail.send()

        const output = {otp, email}
        return output;
    }

    async verifyOtp(email: string, otp: string){
        if(!email || !otp){
            throw new ApiError(StatusHelper.status200Ok, 'Both email and otp are required for verification')
        }

        const isOtpValid = await this.otpRepository.findOtpByEmail(email);
        if(!isOtpValid){
            throw new ApiError(StatusHelper.error404NotFound, 'email is invalid')
        }

        if(otp !== isOtpValid.otp){
            throw new ApiError(StatusHelper.error401Unauthorized, 'Invalid otp')
        }

        if(!(Date.now()+0 < isOtpValid.otpExpiration)){
            throw new ApiError(StatusHelper.error401Unauthorized, 'otp is expired')
        }

        const token = JwtWrapper.sign({email}, ConstantHelper.JWT_SECRET_KEY);

        return token;
    }

    async resetPassword(token: string, newPassword: string, confirmPassword: string){
        if(!token){
            throw new ApiError(StatusHelper.error404NotFound, 'token is required')
        }

        if(!newPassword || !confirmPassword){
            throw new ApiError(StatusHelper.error400BadRequest, 'All fields are required, {newPassword, confirmPassword}')
        }

        if(newPassword !== confirmPassword){
            throw new ApiError(StatusHelper.error400BadRequest, 'Password and confirmPassword values are different')
        }

        const decodedToken = JwtWrapper.verify(token, ConstantHelper.JWT_SECRET_KEY);
        if(!decodedToken || typeof decodedToken === 'string'){
            throw new ApiError(StatusHelper.error401Unauthorized, 'Invalid token')
        }

        const { email } = decodedToken as {email: string};
        const user: any = await this.userRepository.findUserByEmail(email);

        const hashed = await BcryptWrapper.hash(newPassword);

        const updatedUser = await this.userRepository.updateUserPasswordById(user._id, hashed);

        return updatedUser
    }

    async deleteUser(user: any, id: any){
        const loggedInUser = user;
        if(loggedInUser.role !== 'admin'){
            throw new ApiError(StatusHelper.error403Forbidden, 'only admin can access this route')
        }

        if(!isValidObjectId(id)){
            throw new ApiError(StatusHelper.error400BadRequest, 'User id not valid');
        }

        const userDetails: any = await this.userRepository.findUserById(id);
        if(!userDetails){
            throw new ApiError(StatusHelper.error404NotFound, 'user with this id not found')
        }

        // delete the user
        await this.userRepository.deleteUserById(id);

        return {email: userDetails.email}
    }

    async getAllUser(user: any, pageNo: any){
        const loggedInUser = user;
        // check whether the logged in user is admin or not
        if(loggedInUser.role !== 'admin'){
            throw new ApiError(StatusHelper.error403Forbidden, 'only admin can access this route')
        }

        const page: number = Number(pageNo) || 1;
        const perPage = 3;
        const totalUsers = await this.userRepository.countTotalUsers();
        const totalPages = Math.ceil(totalUsers / perPage);

        if(pageNo > totalPages){
            throw new ApiError(StatusHelper.error400BadRequest, `page value exceed the total page count, Total pages= ${totalPages}`)
        }

        const users = await this.userRepository.allUsersWithPagination(page, perPage);

        return {users, page, totalPages}
    }

}