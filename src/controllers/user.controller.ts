import mongoose, {isValidObjectId} from "mongoose";
import { IUser, UserModel } from "../models/user.model";
import express, { NextFunction, Request, Response } from 'express';
import { ApiError } from "../utils/ApiError";
import { ApiResponse } from "../utils/ApiResponse";
import { BcryptWrapper } from "../wrappers/bcrypt.wrapper";
import { JwtWrapper } from "../wrappers/jwt.wrapper";
import { ConstantHelper } from "../constants";
import { OtpWrapper } from "../wrappers/otp.wrapper";
import { OtpModel } from "../models/otp.model";
import { OtpMailer } from "../wrappers/otp-mail.wrapper";
import { StatusHelper } from "../helpers/status.helper";
import UserService from "../services/user.service";

export default class UserController {
    public userServices: UserService;

    constructor(userServices: UserService) {
        this.userServices = userServices;
    }

    async register(req: Request, res: Response, next: NextFunction){
        try {
            const user = await this.userServices.registerUser(req.body);
            return res.status(StatusHelper.status201Created).json(ApiResponse.create(StatusHelper.status200Ok, user, 'User registered successfully'))
        } catch (error) {
            next(error)
        }
    }

    async login(req: Request, res: Response, next: NextFunction){
        try {
            const loggedInUser = await this.userServices.loginUser(req.body)
            const cookieOptions = {maxAge: 24*60*60* 1000} // 24 hours
            return res.status(StatusHelper.status200Ok).cookie('accessToken', loggedInUser.token, cookieOptions).json(ApiResponse.create(StatusHelper.status200Ok, loggedInUser, 'User login successfully'))
        } catch (error) {
            next(error)
        }
    }

    async currentUser(req: Request, res: Response, next: NextFunction){
        try {
            return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok, req.user, 'current user fetched successfully')) 
        } catch (error) {
            next(error)
        }
    }

    async logout(req: Request, res: Response, next: NextFunction){
        try {
            return res.status(StatusHelper.status200Ok).clearCookie('accessToken').json(ApiResponse.create(StatusHelper.status200Ok, {}, 'User logout successfully'))
        } catch (error) {
            next(error)
        }
    }

    async changePassword(req: Request, res: Response, next: NextFunction){
        try {
            const loggedInUser = req.user;
            const requestBody = {
                oldPassword: req.body.oldPassword,
                newPassword: req.body.newPassword,
                confirmPassword: req.body.confirmPassword
            }

            const updatedUser = await this.userServices.changePassword(loggedInUser, requestBody);
            return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok, updatedUser, 'Password changed sucessfully'))
        } catch (error) {
            next(error)
        }
    }

    async forgotPassword(req: Request, res: Response, next: NextFunction){
        try {
            const output = await this.userServices.forgotPassword(req.body.email);
            return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok,output,`Otp successfully sent`))
        } catch (error) {
            next(error)
        }
    }

    async verifyOtp(req: Request, res: Response, next: NextFunction){
        try {
            const token = await this.userServices.verifyOtp(req.body.email, req.body.otp);
            return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok, token, 'Otp verified successfully'))
        } catch (error) {
            next(error)
        }
    }

    async resetPassword(req: Request, res: Response, next: NextFunction){
        try {
            const updatedUser = await this.userServices.resetPassword(req.params.token, req.body.newPassword, req.body.confirmPassword);
            return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok,{}, `${updatedUser?.name.firstName} your account password reset successfully`))
        } catch (error) {
            next(error)
        }
    }

    async deleteUser(req: Request, res: Response, next: NextFunction){
        try {
            const deletedUser = await this.userServices.deleteUser(req.user, req.params.userId);
            return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok, {}, `Account with email: ${deletedUser.email} deleted successfully`) )
        } catch (error) {
            next(error)
        }
    }

    async getAllUsers(req: Request, res: Response, next: NextFunction){
        try {
            const users = await this.userServices.getAllUser(req.user, req.query.page);
            return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok, users, 'All users fetched successfully'))
        } catch (error) {
            next(error)
        }
    }
}


const registerUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { firstName, lastName, username, email, password, role } = req.body;

        // Check if all required fields are present
        if ([firstName, lastName, username, email, password].some((item: string) => !item.trim())) {
            throw new ApiError(StatusHelper.error400BadRequest, "All fields are required");
        }

        // Check if the user with the provided username or email already exists
        const existedUser = await UserModel.findOne({
            $or: [{ username }, { email }]
        });

        if (existedUser) {
            throw new ApiError(StatusHelper.error409Conflict, 'User with email or username already exists');
        }

        // Hash the user's password
        const hashedPassword = await BcryptWrapper.hash(password);

        // Create the new user
        const user = await UserModel.create({
            name: { firstName, lastName },
            username,
            email,
            password: hashedPassword,
            role
        });

        // Retrieve the created user without the password field
        const createdUser = await UserModel.findById(user._id).select("-password");
        if (!createdUser) {
            throw new ApiError(StatusHelper.error400BadRequest, 'Something went wrong while creating the user');
        }

        // Respond with the newly created user
        return res.status(StatusHelper.status201Created).json(ApiResponse.create(StatusHelper.status200Ok, createdUser, "User registered successfully"));

    } catch (error) {
        next(error); // Pass the error to the error-handling middleware
    }
}


const loginUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const {username, email, password} = req.body;

        if(!username && !email) {
            throw new ApiError(StatusHelper.error400BadRequest, 'username or email is required');
        }

        const user = await UserModel.findOne({
            $or : [{username},{email}]
        });
        if(!user){
            throw new ApiError(StatusHelper.error404NotFound, "User with email or username does not exist")
        }

        const hashedPassword = user.password;

        const isPasswordValid = await BcryptWrapper.compare(password, hashedPassword);

        if(!isPasswordValid) {
            throw new ApiError(StatusHelper.error401Unauthorized, "Invalid user credential");
        }

        const loggedInUser = await UserModel.findById(user._id).select("-password")

        const payload = {
            id : loggedInUser?._id,
        }
        const secretKey = ConstantHelper.JWT_SECRET_KEY;
        const options = {
            expiresIn: '1h'
        }

        const token = JwtWrapper.sign(payload, secretKey, options);

        const cookieOptions = {
            httpOnly: true,
            maxAge: 5 * 60 * 1000,
            secure: false,
        }

        return res.status(StatusHelper.status200Ok).cookie("accessToken", token, cookieOptions).json(ApiResponse.create(StatusHelper.status200Ok, loggedInUser, "user login successfully"));

    } catch (error) {
        next(error);
    }
}

const getCurrentUser = async(req: Request, res: Response, next: NextFunction) =>  {
    try {
        const user = req.user;

        return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok, {"user":user}, "User details fetched successfully" ));

    } catch (error) {
        next(error);
    }
}

const logout = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = req.user;
        if(!user){
            throw new ApiError(StatusHelper.error401Unauthorized, "Unauthorized")
        }
        const cookieOptions = {
            httpOnly: true,
            secure: false,
        }
        return res.status(StatusHelper.status200Ok).clearCookie("accessToken", cookieOptions).json(ApiResponse.create(StatusHelper.status200Ok, {}, "User logout successfuly"))
    } catch (error) {
        
    }
}

// PAGINATION IMPLEMENT // ADMIN PROTECTED ROUTE
const getAllUser = async (req: Request, res: Response, next:NextFunction) => {
    try {
        const user = req.user;
    
        if(user?.role !== 'admin'){
            throw new ApiError(StatusHelper.error401Unauthorized, "Only admin can fetch user's details");
        }

        // PAGINATION
        const page = Number(req.query.page) || 1;
        const perPage = 3;
        const totalUsers = await UserModel.countDocuments();
        const totalPages = Math.ceil(totalUsers / perPage);

        // handling the error for the case when user passed a page number in a query param which is greater than our total pages value.
        if(page > totalPages){
            throw new ApiError(StatusHelper.error400BadRequest, 'page value exceed the totalPage count')
        }
    
        const allUsers = await UserModel.find({}, "-password")
        .skip((page - 1) * perPage)
        .limit(perPage)
        .exec();
    
        const filteredUsers = allUsers.filter((user) => user.role !== 'admin');
        
        return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok, {allUsers, totalPages, page}, 'All user fetched successfully'));
    } catch (error) {
        next(error);
    }
}

// ADMIN PROTECTED ROUTE
const deleteUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user: any = req.user;
        if(user.role !== 'admin') {
            throw new ApiError(StatusHelper.error401Unauthorized, 'Unauthorized Request, Admin protected route')
        }

        // Extract userId from params
        const {userId} = req.params;

        if(!(isValidObjectId(userId))){
            throw new ApiError(StatusHelper.error400BadRequest, 'userId is not valid')
        }
        
        // now delete the user from db
        await UserModel.findByIdAndDelete(userId);

        return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok,{}, 'user deleted successfully'))

    } catch (error) {
        next(error);
    }
}

const changePassword = async(req: Request, res: Response, next: NextFunction) => {
    try {
        const {oldPassword, newPassword, confirmPassword} = req.body;

        if(!oldPassword || !newPassword || !confirmPassword){
            throw new ApiError(StatusHelper.error400BadRequest, "All fields are required: oldPassword, newPassword, confirmPassword")
        }

        if(newPassword !== confirmPassword ){
            throw new ApiError(StatusHelper.error400BadRequest, 'value of newPassword and confirmPassword are different');
        }
        const loggedInUser = req.user;
        const user = await UserModel.findById(loggedInUser?._id);

        const userOldPassword : string = String(user?.password);

        const isPasswordValid = await BcryptWrapper.compare(oldPassword, userOldPassword);
        if(!isPasswordValid){
            throw new ApiError(StatusHelper.error401Unauthorized, 'Invalid old password');
        }

        const hashedPassword = await BcryptWrapper.hash(newPassword);

        const updatedUser = await UserModel.findByIdAndUpdate(user?._id, {password: hashedPassword});

        return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok, {}, 'Password changed successfully'))

    } catch (error) {
        next(error)
    }
}

const forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Extract email from the request body
        const { email } = req.body;

        // Validate the email input; if it's missing or empty, return a 400 error
        if (!email || email.trim() === '') {
            return next(new ApiError(StatusHelper.error400BadRequest, 'Email is required'));
        }

        // Check if a user with the provided email exists in the database
        const isUserExist = await UserModel.findOne({ email });
        if (!isUserExist) {
            return next(new ApiError(StatusHelper.error400BadRequest, 'User with this email is not registered'));
        }

        let otp;
        // Generate a unique OTP; keep generating if a collision is found in the database
        do {
            otp = OtpWrapper.generate();
            if (!otp) {
                return next(new ApiError(StatusHelper.error500InternalServerError, 'Error while generating OTP'));
            }
        } while (await OtpModel.findOne({ otp }));

        // Delete any existing OTP associated with this email in the database
        await OtpModel.deleteOne({ email });

        // Save the newly generated OTP in the database
        const otpDocument = await OtpModel.create({ email, otp });

        // sending email
        const otpMail = OtpMailer.create(otp, email);
        await otpMail.send();

        // Respond with a success message and the OTP document
        return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok, otpDocument, 'OTP generated successfully'));

    } catch (error) {
        // Pass any errors to the error-handling middleware
        next(error);
    }
};

const verifyOTP = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Extract OTP from the request body
        const { otp } = req.body;

        // Validate OTP; if it's missing or empty
        if (!otp || otp.trim() === "") {
            return next(new ApiError(StatusHelper.error400BadRequest, "OTP is required"));
        }

        // Check if the provided OTP exists in the database
        const otpDocument = await OtpModel.findOne({ otp });

        // If OTP is not found or Invalid
        if (!otpDocument) {
            return next(new ApiError(StatusHelper.error401Unauthorized, "OTP is invalid or expired"));
        }

        const email = otpDocument.email;

        // Generate a JWT token for the verified user
        const token = JwtWrapper.sign(
            { email }, 
            ConstantHelper.JWT_SECRET_KEY, 
            { expiresIn: "5m" }
        );

        // Delete the OTP from the database as it has been used
        await OtpModel.deleteOne({ otp });

        // Respond with the generated token
        return res.status(200).json(ApiResponse.create(StatusHelper.status200Ok, { token }, "OTP verified successfully"));
        
    } catch (error) {
        // Pass any errors to the error-handling middleware
        next(error);
    }
};


const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { token } = req.params;
        const { password, confirmPassword } = req.body;

        if (!password || !confirmPassword || password.trim() === '' || confirmPassword.trim() === '') {
            return next(new ApiError(StatusHelper.status200Ok, 'Password and confirm password fields are required'));
        }

        // Check if passwords match
        if (password !== confirmPassword) {
            return next(new ApiError(StatusHelper.status200Ok, 'Password and confirm password do not match'));
        }

        // Verify the token
        const decodedToken = JwtWrapper.verify(token, ConstantHelper.JWT_SECRET_KEY);

        // Ensure decodedToken is an object with an email property
        if (typeof decodedToken !== 'object' || !decodedToken || !('email' in decodedToken)) {
            return next(new ApiError(StatusHelper.error401Unauthorized, "Invalid or expired Access Token"));
        }

        // Fetch the user using the decoded token payload
        const user = await UserModel.findOne({ email: (decodedToken as { email: string }).email }).select("-password");
        if (!user) {
            return next(new ApiError(StatusHelper.error404NotFound, "User not found"));
        }

        // Hash the new password
        const hashedPassword = await BcryptWrapper.hash(password);

        // Update the user's password
        await UserModel.findByIdAndUpdate(user._id, { password: hashedPassword });

        // success response
        return res.status(StatusHelper.status200Ok).json(ApiResponse.create(StatusHelper.status200Ok, {}, "Password reset successfully"));
    } catch (error) {
        // Pass any errors to the error-handling middleware
        next(error);
    }
};



export { registerUser, 
         loginUser, 
         getCurrentUser, 
         logout, 
         getAllUser, 
         changePassword, 
         forgotPassword, verifyOTP, resetPassword,
         deleteUser 

};
