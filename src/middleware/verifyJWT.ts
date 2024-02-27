import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import connectToMongoDB from "../db/index";
import { ObjectId } from "mongodb";

declare global {
    namespace Express {
        interface Request {
            user?: any; // Adjust the type according to your user object structure
        }
    }
}

export  const verifyJWT =  async (req: Request, res: Response, next: NextFunction) => {
    try {
        // console.log("Verify JWT", req.cookies.refreshToken)
        const token = req.header("Authorization")?.replace("Bearer ", "");
        // console.log(token)
        // console.log(req.body)
        if (!token) {
            throw new Error("Unauthorized request");
        }

        const decodedToken: any = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        
        const db = await connectToMongoDB();
        const user = await db.collection("user").findOne({_id: new ObjectId(decodedToken?._id)});
        // console.log("user exist: ",user)
        if (!user) {
            throw new Error("Invalid Access Token");
        }

        req.user = user;
        next();
    } catch (error) {
        console.log(error.message)
        // if(error.message === "jwt expired"){
        //     res.status(403).json({
        //         success:false,
        //         message:"Session Expired, Please login again"
        //     })
        // }
        // throw new Error(error?.message || "Invalid access token");
        res.status(error.code || 403).json({
            success:false,
            message:error.message === "jwt expired" ? "Session Expired, Please login again" : error.message
        })
    }
};
