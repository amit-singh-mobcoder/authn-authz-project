import express, {Router} from 'express'
const router = Router();

import { registerUser, loginUser } from '../controllers/user.controller';


router.route('/signup').post(registerUser);
router.route('/login').post(loginUser);

export default router;