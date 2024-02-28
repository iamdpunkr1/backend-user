import {register, loginUser, logoutUser, uploadImages, forgotPassword, resetPassword, refreshAccessToken} from "../controllers/userController";
import { verifyJWT } from "../middleware/verifyJWT"
import { Router } from "express";
import { upload } from "../middleware/multerMiddleware";
const router = Router();

router.route("/api/register").post(register);
router.route("/api/login").post(loginUser);
router.route("/api/logout").get(logoutUser);
router.route("/api/upload").post(verifyJWT,upload.single("actualImage"), uploadImages);   
router.route("/api/forgot-password").post(forgotPassword);
router.route("/api/reset-password/:id/:token").post(resetPassword);
router.route("/api/refresh").get(refreshAccessToken);

export default router;