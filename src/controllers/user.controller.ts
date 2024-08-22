import { UserModel } from "../models/user.model";
import express, { NextFunction, Request, Response } from 'express';
import { ApiError } from "../utils/ApiError";
import { ApiResponse } from "../utils/ApiResponse";
import { BcryptWrapper } from "../wrappers/bcrypt.wrapper";
import { JwtWrapper } from "../wrappers/jwt.wrapper";
import { ConstantHelper } from "../constants";

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
            throw new ApiError(404, "User does not exist")
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
            secure: true,
        }

        return res.status(200).cookie("accessToken", token, cookieOptions).json(ApiResponse.create(200, loggedInUser, "user loggedin successfully"));

    } catch (error) {
        next(error);
    }
}

export { registerUser, loginUser };
