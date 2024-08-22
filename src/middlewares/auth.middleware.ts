import express, {Request, Response, NextFunction} from 'express';
import { ApiError } from '../utils/ApiError';
import { JwtWrapper } from "../wrappers/jwt.wrapper";
import { ConstantHelper } from '../constants';
import { UserModel } from '../models/user.model';

const verifyJWT = (req: Request, res: Response, next: NextFunction) => {

    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
    
        if (!token){
            throw new ApiError(401, "Unauthorized request")
        }
        
        const secretKey = ConstantHelper.jwtSecretKey;
        const decodedToken = JwtWrapper.verify(token, secretKey);
    
        const user = UserModel.findById(decodedToken?.id)
    
        if (!user) {
            throw new ApiError(401, "Invalid Access Token")
        }
    
        req.user = user;
        next();

    } catch (error) {
    }

}