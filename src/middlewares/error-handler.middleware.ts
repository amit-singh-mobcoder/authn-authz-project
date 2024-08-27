import { ApiError } from "../utils/ApiError";
import express,{Request, Response, NextFunction} from 'express';

const errorHandler = (err: ApiError | Error, req: Request, res: Response, next: NextFunction) => {
    if (err instanceof ApiError) {
        res.status(err.statusCode).json({
            success: err.success,
            message: err.message,
            errors: err.errors,
            stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
        });
    } else {
        res.status(500).json({
            success: false,
            message: 'Internal Server Error',
            stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
        });     
    }
};

export default errorHandler;
