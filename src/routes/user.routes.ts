// import express, {Router} from 'express'
// import UserController from '../controllers/user.controller'
// import UserService from '../services/user.service';
// import UserRepository from '../repositories/user.repository';

// class UserRouter {
//     router: Router;
//     userController: UserController;
//     userService: UserService;
//     userRepository: UserRepository;

//     constructor(userController: UserController, userService: UserService, userRepository: UserRepository){
//         this.router = express.Router();
//         this.userController = userController;
//         this.userService = userService;
//         this.userRepository = userRepository;
//         this.setRoutes();
//     }

//     setRoutes(){
//         this.router.route('/register').post(this.userController.register.bind(this.userController))
//     }
// }

// export {UserRouter};

import express, {Router} from 'express'
const router = Router();

import { registerUser, loginUser, getCurrentUser, logout, getAllUser, changePassword, forgotPassword, verifyOTP, resetPassword, deleteUser } from '../controllers/user.controller';
import { verifyJWT } from '../middlewares/auth.middleware';

import UserService from '../services/user.service';
import UserRepository from '../repositories/user.repository';
import UserController from '../controllers/user.controller';
import OtpRepository from '../repositories/otp.repository';
import OtpService from './otp.service';

const otpRepository = new OtpRepository()
const userRepository = new UserRepository();
const userService = new UserService(userRepository, otpRepository);
const userController = new UserController(userService);


router.route('/signup').post(userController.register.bind(userController));
router.route('/login').post(userController.login.bind(userController));
router.route('/current-user').get(verifyJWT, userController.currentUser.bind(userController));
router.route('/logout').post(verifyJWT, userController.logout.bind(userController));

router.route('/change-password').patch(verifyJWT, userController.changePassword.bind(userController));

router.route('/forgot-password').post(userController.forgotPassword.bind(userController));

router.route('/verify-otp').post(userController.verifyOtp.bind(userController));
router.route('/reset-password/:token').patch(resetPassword);



// admin protected routes
router.route('/').get(verifyJWT, getAllUser);
router.route('/delete/:userId').post(verifyJWT, deleteUser);

export default router;