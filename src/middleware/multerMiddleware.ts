import multer from "multer";
import { Request } from "express";
import path from "path";

const storage = multer.diskStorage({
    destination: function (req: Request, file: Express.Multer.File, cb: (error: Error | null, destination: string) => void) {
        cb(null, "./public/temp");
    },
    filename: function (req: Request, file: Express.Multer.File, cb: (error: Error | null, filename: string) => void) {
        const extension = path.extname(file.originalname);
        const filenameWithoutExtension = path.basename(file.originalname, extension);
        cb(null, `${filenameWithoutExtension}-${Date.now()}${extension}`);
    }
});

export const upload = multer({ 
    storage, 
});
