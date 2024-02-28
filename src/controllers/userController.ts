import { Request, Response } from "express";
import mongo from "../db/index";
import asyncHandler from "../utils/asyncHandler";
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"
import { ObjectId } from "mongodb";
import nodemailer from "nodemailer";
import { saveBase64Image } from "../utils/saveImage";
import { ApiError } from "../utils/ApiError";
// import mongo from "../utils/mongo";

// console.log("User Controller", mongo);
// const {Users} = mongo;

enum Hobbies {
  reading = "reading",
  sports = "sports",
  singing = "singing",
  travelling = "travelling",
}

const resetLinkExpiryTime:number =  86400000; // 24 hours in milliseconds
const passwordResetInterval:number = 3600000; // 1 hour in milliseconds

const generateAccessToken = function(){
  return jwt.sign(
      {
          _id: this._id,
          email: this.email,
          username: this.username,
      },
      process.env.ACCESS_TOKEN_SECRET,
      {
          expiresIn: process.env.ACCESS_TOKEN_EXPIRY
      }
  )
}

const generateRefreshToken = function(){
  return jwt.sign(
      {
          _id: this._id,
          
      },
      process.env.REFRESH_TOKEN_SECRET,
      {
          expiresIn: process.env.REFRESH_TOKEN_EXPIRY
      }
  )
}

const generateHashedPassword = async (password:string): Promise<string> => {
    return await bcrypt.hash(password,10);
}

const isPasswordCorrect = async (password:string, dbPassword:string): Promise<boolean> => {
    return await bcrypt.compare(password, dbPassword);
}

// cookie settings
const options = {
    httpOnly: true,
    expires: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000),
    // secure:true,
    // maxAge: 24 * 60 * 60 * 1000 
}

const register = asyncHandler( async (req: Request, res: Response) => {

        const { username, email, password, address, phone, gender, hobbies } = req.body;
        
        if ([username, email, password, address, phone, gender].some(field => field.trim() === "")) {
            throw new ApiError(400, "All fields are required");
        }

        if(!(username.length > 4 && username.length<25) ) throw new ApiError(400,"Username must be between 4-25 characters")
        
        // Validate UserName
        const USER_REGEX = /^[A-z][A-z0-9-_]{3,23}$/;
        if(!USER_REGEX.test(username)) throw new ApiError(400,"Invalid Username")

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            throw new ApiError(400, "Invalid email format");
        }

        const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%])/;
        if( !passRegex.test(password)){
            throw new ApiError(400,"Password must contain at least one uppercase letter, one lowercase letter, one number and one special character");
        }
        // Validate password length
        if (password.length < 8) {
            throw new ApiError(400,"Password must be at least 8 characters long");
        }

        // Validate phone number format (assuming it should start with a '+' followed by digits)
        const phoneRegex = /^\d{1,}$/;
        if (phone.length > 10) {
            throw new ApiError(400,"Invalid phone number format");
        }

        // Additional validation for gender (assuming only 'male', 'female', or 'other' are valid)
        if (!['male', 'female'].includes(gender.toLowerCase())) {
            throw new ApiError(400, "Invalid gender");
        }

        // Additional validation for hobbies (assuming it's an array of strings)
        if (!Array.isArray(hobbies) || !hobbies.every(hobby => Object.values(Hobbies).includes(hobby))) {
          throw new ApiError(400,"Hobbies must be an array of valid options: reading, sports, singing, travelling");
        }

        const {Users} =  mongo;
        // const collection = db.collection("user");
        
        const existedUser = await Users.findOne({ $or: [{ username}, {email}] });
        if (existedUser) throw new ApiError(409,"User already exists");

        const hashPassword = await generateHashedPassword(password);
        const result = await Users.insertOne({ username, email, password:hashPassword, address, phone, gender, hobbies, images:[]});

        if(!result) throw new ApiError(500,"Something went wrong while registering the user");

        res.status(201).json(result);

})


const loginUser = asyncHandler(async (req:Request, res:Response)=>{
  
  const {username, password} = req.body;
  

  if(!username || !password) throw new ApiError(400,"All fields are required")

    // Validate UserName
    const USER_REGEX = /^[A-z][A-z0-9-_]{3,23}$/;
    if(!USER_REGEX.test(username)) throw new ApiError(400,"Invalid Username")


  // Validate password length
  if (password.length < 8) {
      throw new ApiError(400,"Password must be at least 8 characters long");
  }

  const {Users} =  mongo;
  
  const user = await Users.findOne({username})
  if(!user) throw new ApiError(404,"User doesn't exist")


  if(!(await isPasswordCorrect(password, user.password))) throw new ApiError(401,"Invalid User Credentials")
 
  const accessToken = await generateAccessToken.call(user);
  const refreshToken =await generateRefreshToken.call(user);
  

  // Exclude password field from user object
  const { password: _,_id:id, refreshToken:rfsh, ...userWithoutPassword } = user;
  // Update user information, for example, last login timestamp
  await Users.updateOne(
    { username },
    { $set: { refreshToken } }
  );

  res.status(200).cookie("refreshToken", refreshToken, options).json({ ...userWithoutPassword, accessToken });

});


const logoutUser = asyncHandler(async(req, res) => {
  
  const cookies = req.cookies;

    if (!cookies?.refreshToken) {
       res.status(204).json("User already logged out");
      }

  const refreshToken = req.cookies.refreshToken;

  const { Users } = mongo;

  const foundUser = await Users.findOneAndUpdate(
    { refreshToken},
    { $set: { refreshToken: '' } }
    );

  if (!foundUser) {
    res.status(204)
    .clearCookie("refreshToken", options)
    .json("User already logged Out");
  }

  // await collection.updateOne(
  //   { refreshToken:"" },
  //   { $set: { refreshToken: '' } }
  // );


  console.log("logout validation completed")
   res
  .status(200)
  .clearCookie("refreshToken", options)
  .json("User logged Out")
})



const uploadImages =  asyncHandler(async (req:Request, res:Response)=>{
    const image = req.body.image;
    // const {image, actualImage} = req.body;
    const {filename} = req.file;

    const {_id} = req.user;
    console.log("uploading image")

    if(!image) throw new ApiError(400,"Invalid Image");
    if(!filename) throw new ApiError(500,"Server Error, Failed to save image");
    const { Users } = mongo;

    const filter = { _id: new ObjectId(_id) };
    const updatedUser = await Users.findOne(filter);
    
    if(!updatedUser) throw new ApiError(404, "User doesn't exist");

    if(updatedUser.images.length >= 5) {
        throw new ApiError(400,"You can only upload 5 images");
    }

    
    try{   
        // const filename = await saveBase64Image(actualImage);

        const update:any = { $push: { images: {thumbnail:image,
            cdUrl: filename } } };
        await Users.findOneAndUpdate(filter, update);
        
        const updatedUser2 = await Users.findOne(filter);
        console.log("uploaded")
        res.status(201).json({ message: "Upload Successful", newImages: updatedUser2.images });
    } catch (error) {
        throw new ApiError(500,"Failed to save image")
    }

    

});




const forgotPassword = asyncHandler(async (req: Request, res: Response) => {
    const { email } = req.body;
  
    // Input validation
    if (!email) {
        throw new ApiError(400,'Email is required');
    }
  
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        throw new ApiError(400,'Invalid email format');
    }
  
    // Connect to MongoDB
    const {Users} = mongo;
  
    // Check if user exists
    const user = await Users.findOne({ email });
    if (!user) {
        throw new ApiError(404,'User does not exist');
    }

    // Check if the user has recently generated a reset link
    if (user.resetLinkGeneratedAt && Date.now() - user.resetLinkGeneratedAt < resetLinkExpiryTime) {
        const remainingTime = resetLinkExpiryTime - (Date.now() - user.resetLinkGeneratedAt);
        return res.status(429).json({ message: `Reset link can only be generated once in 24hrs. Please try again after 24hrs.` });
    }

    // Generate JWT token (use Base64 encoding or JWTs)
    const token = jwt.sign({ userId: user._id }, process.env.FORGOT_PASSWORD_SECRET, { expiresIn: "1h" });
    const encodedToken = Buffer.from(token).toString("base64"); // Base64 encoding example

    // Create reset password link
    const resetUrl = `http://localhost:5173/reset-password/${user._id}/${encodedToken}`;

    // Update the user's reset link generation timestamp
    await Users.updateOne({ email }, { $set: { resetLinkGeneratedAt: Date.now() } });
  
    // Prepare email content
    const mailOptions = {
        from: process.env.EMAIL_ID,
        to: email,
        subject: 'Reset Password Link',
        text: `
            You are receiving this because you (or someone else) has requested the reset of the password for your account.
            The reset link will expire in 1 hour.
            Please click on the following link to reset your password:
            ${resetUrl}
        `,
    };
  
    // Send email using a secure transport
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_ID, 
            pass: process.env.EMAIL_PASSWORD, 
        },
    });
  
    try {
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Reset Password Link has been sent to your email' });
    } catch (error) {
        throw new ApiError(500, error?.message || "Failed to send reset password link")
    }
});
  



const resetPassword = asyncHandler(async (req: Request, res: Response) => {
    const { id, token } = req.params;
    const { password } = req.body;
  
    // Input validation
    if (!password) {
        throw new ApiError(400,'Password is required');
    }
  
    if (!ObjectId.isValid(id)) {
        throw new ApiError(400,'Invalid user ID');
    }
  
    if (password.length < 8) {
        throw new ApiError(400,'Password must be at least 8 characters long');
    }

    // Decode token (if using Base64 encoding)
    const decodedUserToken = Buffer.from(token, "base64").toString();
  
    // Decode JWT token (replace algorithm if different)
    const decodedToken: any =  jwt.verify(decodedUserToken, process.env.FORGOT_PASSWORD_SECRET);
  
    if (!decodedToken || !decodedToken.userId || decodedToken.userId !== id) {
        throw new ApiError(400,'Invalid or expired reset password token');
    }

    // Check if the user has recently reset their password
    const {Users} = mongo;
    const user = await Users.findOne({ _id: new ObjectId(id) });

    if (user && user.lastPasswordReset && Date.now() - user.lastPasswordReset < passwordResetInterval) {
        const remainingTime = passwordResetInterval - (Date.now() - user.lastPasswordReset);
        return res.status(429).json({ message: `You can only reset your password once in 1 hour. Please try again after ${Math.ceil(remainingTime / 3600000)} hour.` });
    }

    // Hash and update password
    const hashedPassword = await bcrypt.hash(password, 10);
    await Users.updateOne({ _id: new ObjectId(id) }, { $set: { password: hashedPassword, lastPasswordReset: Date.now() } });
  
    res.status(200).json({ message: 'Password reset successfully' });
});



const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    console.log("refresh token", incomingRefreshToken)
    if (!incomingRefreshToken) {
        throw new ApiError(401,"Unauthorized request")
    }

    try {
        const decodedToken:any = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
          
        const {Users} = mongo;
        // console.log(decodedToken?._id)
        const user = await Users.findOne({_id: new ObjectId(decodedToken?._id)})
    
        if (!user) {
            throw new ApiError(401,"Invalid refresh token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401,"Refresh token is expired or used")
            
        }
    
    
        const accessToken = await generateAccessToken.call(user);
        const { password: _,_id:id, refreshToken:rfsh, ...userWithoutPassword } = user;
        return res
        .status(200)
        .json({...userWithoutPassword,  accessToken});

    } catch (error) {
        throw new ApiError(401,  "Invalid refresh token")
    }

})

  
export {register, loginUser, logoutUser, uploadImages, forgotPassword, resetPassword, refreshAccessToken};
