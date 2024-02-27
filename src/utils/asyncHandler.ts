import { Request, Response, NextFunction } from "express";

type functionProps = (req:Request, res:Response,) => Promise<any>

const asyncHandler = (fn: functionProps) => async (req:Request, res:Response,  next:NextFunction) => {
    try{
       await fn(req, res);
    }catch(error){
        res.status(error.code || 500).json({
            success:false,
            message:error.message === "jwt expired" ? "Session Expired, Please login again" : error.message
        })
    }
}

export default asyncHandler