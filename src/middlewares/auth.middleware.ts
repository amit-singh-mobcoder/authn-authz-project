import express, {Request, Response, NextFunction} from 'express';
import { ApiError } from '../utils/ApiError';
import { JwtWrapper } from "../wrappers/jwt.wrapper";
import { ConstantHelper } from '../constants';
import { UserModel, IUser } from '../models/user.model';

declare module 'express-serve-static-core' {
    interface Request {
        user?: IUser | null;  // Add optional user property to Request interface
    }
}

const verifyJWT = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")

        if (!token) {
            throw new ApiError(401, "Unauthorized request");
        }

        const secretKey = ConstantHelper.JWT_SECRET_KEY;
        const decodedToken = JwtWrapper.verify(token, secretKey);

        // Ensure decodedToken is an object with an id property
        if (typeof decodedToken !== 'object' || !decodedToken || !('id' in decodedToken)) {
            throw new ApiError(401, "Invalid Access Token");
        }

        // Access the id property safely
        const user = await UserModel.findById((decodedToken as { id: string }).id).select("-password");

        if (!user) {
            throw new ApiError(401, "Invalid Access Token");
        }

        // Attach the user to the request object
        req.user = user;
        next();
    } catch (error) {
        next(error);
    }
}



export { verifyJWT }