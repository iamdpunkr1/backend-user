import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import mongo from "../db/index";
import { ObjectId } from "mongodb";
import asyncHandler from "../utils/asyncHandler";
import { ApiError } from "../utils/ApiError";
declare global {
    namespace Express {
        interface Request {
            user?: any; // Adjust the type according to your user object structure
        }
    }
}

export  const verifyJWT =  asyncHandler( async(req: Request, res: Response, next: NextFunction) => {
    try {
        // console.log("Verify JWT", req.cookies.refreshToken)
        const token = req.header("Authorization")?.replace("Bearer ", "");
        // console.log(token)
        // console.log(req.body)
        if (!token) {
            throw new ApiError(403,"Unauthorized request");
        }

        const decodedToken: any = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        
        const {Users} = mongo;
        const user = await Users.findOne({_id: new ObjectId(decodedToken?._id)});
        // console.log("user exist: ",user)
        if (!user) {
            throw new ApiError(403,"Invalid Access Token");
        }

        req.user = user;
        next();
    } catch (error) {
        // console.log(error.message)

        throw new ApiError(403, "Invalid Access Token");
    }
});
