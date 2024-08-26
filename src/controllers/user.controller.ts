import { UserModel } from "../models/user.model";
import express, { NextFunction, Request, Response } from 'express';
import { ApiError } from "../utils/ApiError";
import { ApiResponse } from "../utils/ApiResponse";
import { BcryptWrapper } from "../wrappers/bcrypt.wrapper";
import { JwtWrapper } from "../wrappers/jwt.wrapper";
import { ConstantHelper } from "../constants";
import { OtpWrapper } from "../wrappers/otp.wrapper";
import { OtpModel } from "../models/otp.model";
import { OtpMailer } from "../wrappers/otp-mail.wrapper";

const registerUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { firstName, lastName, username, email, password, role } = req.body;

        // Check if all required fields are present
        if ([firstName, lastName, username, email, password].some((item: string) => !item.trim())) {
            throw new ApiError(400, "All fields are required.");
        }

        // Check if the user with the provided username or email already exists
        const existedUser = await UserModel.findOne({
            $or: [{ username }, { email }]
        });
        if (existedUser) {
            throw new ApiError(409, 'User with email or username already exists.');
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
            throw new ApiError(400, 'Something went wrong while creating the user');
        }

        // Respond with the newly created user
        return res.status(201).json(ApiResponse.create(201, createdUser, "User registered successfully"));

    } catch (error) {
        next(error); // Pass the error to the error-handling middleware
    }
}


const loginUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const {username, email, password} = req.body;

        if(!username && !email) {
            throw new ApiError(400, 'username or email is required');
        }

        const user = await UserModel.findOne({
            $or : [{username},{email}]
        });
        if(!user){
            throw new ApiError(404, "User with email or username does not exist")
        }

        const hashedPassword = user.password;

        const isPasswordValid = await BcryptWrapper.compare(password, hashedPassword);

        if(!isPasswordValid) {
            throw new ApiError(401, "Invalid user credential");
        }

        const loggedInUser = await UserModel.findById(user._id).select("-password")

        const payload = {
            id : loggedInUser?._id,
        }
        const secretKey = ConstantHelper.jwtSecretKey;
        const options = {
            expiresIn: '1h'
        }

        const token = JwtWrapper.sign(payload, secretKey, options);

        const cookieOptions = {
            httpOnly: true,
            maxAge: 5 * 60 * 1000,
            secure: false,
        }

        return res.status(200).cookie("accessToken", token, cookieOptions).json(ApiResponse.create(200, loggedInUser, "user login successfully"));

    } catch (error) {
        next(error);
    }
}

const getCurrentUser = async(req: Request, res: Response, next: NextFunction) =>  {
    try {
        const user = req.user;

        return res.status(200).json(ApiResponse.create(200, {"user":user}, "User details fetched successfully" ));

    } catch (error) {
        next(error);
    }
}

const logout = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = req.user;
        if(!user){
            throw new ApiError(401, "Unauthorized")
        }
        const cookieOptions = {
            httpOnly: true,
            secure: false,
        }
        return res.status(200).clearCookie("accessToken", cookieOptions).json(ApiResponse.create(200, {}, "User logout successfuly"))
    } catch (error) {
        
    }
}

const getAllUser = async (req: Request, res: Response, next:NextFunction) => {
    try {
        const user = req.user;
    
        if(user?.role !== 'admin'){
            throw new ApiError(401, "Only admin can fetch user's details");
        }
    
        const allUsers = await UserModel.find({}, "-password");
    
        const filteredUsers = allUsers.filter((user) => user.role !== 'admin');
        
        return res.status(200).json(ApiResponse.create(200, filteredUsers, 'All user fetched successfully'));
    } catch (error) {
        next(error);
    }
}

const changePassword = async(req: Request, res: Response, next: NextFunction) => {
    try {
        const {oldPassword, newPassword, confirmPassword} = req.body;

        if(!oldPassword || !newPassword || !confirmPassword){
            throw new ApiError(400, "All fields are required: oldPassword, newPassword, confirmPassword")
        }

        if(newPassword !== confirmPassword ){
            throw new ApiError(400, 'value of newPassword and confirmPassword are different');
        }
        const loggedInUser = req.user;
        const user = await UserModel.findById(loggedInUser?._id);

        const userOldPassword : string = String(user?.password);

        const isPasswordValid = await BcryptWrapper.compare(oldPassword, userOldPassword);
        if(!isPasswordValid){
            throw new ApiError(401, 'Invalid old password');
        }

        const hashedPassword = await BcryptWrapper.hash(newPassword);

        const updatedUser = await UserModel.findByIdAndUpdate(user?._id, {password: hashedPassword});

        return res.status(200).json(ApiResponse.create(200, {}, 'Password changed successfully'))

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
            return next(new ApiError(400, 'Email is required'));
        }

        // Check if a user with the provided email exists in the database
        const isUserExist = await UserModel.findOne({ email });
        if (!isUserExist) {
            return next(new ApiError(400, 'User with this email is not registered'));
        }

        let otp;
        // Generate a unique OTP; keep generating if a collision is found in the database
        do {
            otp = OtpWrapper.generate();
            if (!otp) {
                return next(new ApiError(500, 'Error while generating OTP'));
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
        return res.status(200).json(ApiResponse.create(200, otpDocument, 'OTP generated successfully'));

    } catch (error) {
        // Pass any errors to the error-handling middleware
        next(error);
    }
};

const verifyOTP = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Extract OTP from the request body
        const { otp } = req.body;

        // Validate OTP; if it's missing or empty, return a 400 error
        if (!otp || otp.trim() === "") {
            return next(new ApiError(400, "OTP is required"));
        }

        // Check if the provided OTP exists in the database
        const otpDocument = await OtpModel.findOne({ otp });

        // If OTP is not found, return a 401 (Unauthorized) error
        if (!otpDocument) {
            return next(new ApiError(401, "OTP is invalid or expired"));
        }

        const email = otpDocument.email;

        // Generate a JWT token for the verified user
        const token = JwtWrapper.sign(
            { email }, 
            ConstantHelper.jwtSecretKey, 
            { expiresIn: "5m" }
        );

        // Delete the OTP from the database as it has been used
        await OtpModel.deleteOne({ otp });

        // Respond with the generated token
        return res.status(200).json(ApiResponse.create(200, { token }, "OTP verified successfully"));
        
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
            return next(new ApiError(400, 'Password and confirm password fields are required'));
        }

        // Check if passwords match
        if (password !== confirmPassword) {
            return next(new ApiError(400, 'Password and confirm password do not match'));
        }

        // Verify the token
        const decodedToken = JwtWrapper.verify(token, ConstantHelper.jwtSecretKey);

        // Ensure decodedToken is an object with an email property
        if (typeof decodedToken !== 'object' || !decodedToken || !('email' in decodedToken)) {
            return next(new ApiError(401, "Invalid or expired Access Token"));
        }

        // Fetch the user using the decoded token payload
        const user = await UserModel.findOne({ email: (decodedToken as { email: string }).email }).select("-password");
        if (!user) {
            return next(new ApiError(404, "User not found"));
        }

        // Hash the new password
        const hashedPassword = await BcryptWrapper.hash(password);

        // Update the user's password
        await UserModel.findByIdAndUpdate(user._id, { password: hashedPassword });

        // Return success response
        return res.status(200).json(ApiResponse.create(200, {}, "Password reset successfully"));
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
         forgotPassword, verifyOTP, resetPassword 

};
