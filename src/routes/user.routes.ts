import express, {Router} from 'express'
const router = Router();

import { registerUser, loginUser, getCurrentUser, logout, getAllUser, changePassword, forgotPassword, verifyOTP, resetPassword, deleteUser } from '../controllers/user.controller';
import { verifyJWT } from '../middlewares/auth.middleware';


router.route('/signup').post(registerUser);
router.route('/login').post(loginUser);
router.route('/current-user').get(verifyJWT, getCurrentUser);
router.route('/logout').post(verifyJWT, logout);
router.route('/change-password').patch(verifyJWT, changePassword);

router.route('/forgot-password').post(forgotPassword);
router.route('/verify-otp').post(verifyOTP);
router.route('/reset-password/:token').patch(resetPassword);



// admin protected routes
router.route('/').get(verifyJWT, getAllUser);
router.route('/delete/:userId').post(verifyJWT, deleteUser);

export default router;