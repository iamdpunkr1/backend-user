import { Request, Response, NextFunction } from "express";

type functionProps = (req:Request, res:Response, next:NextFunction) => Promise<any>

const asyncHandler = (fn: functionProps) => async (req:Request, res:Response,  next:NextFunction) => {
    try{
       await fn(req, res, next);
    }catch(error){

        res.status(error.statusCode || 500).json({
            success:false,
            message: error.message || "Something went wrong"
        })
    }
}

export default asyncHandler