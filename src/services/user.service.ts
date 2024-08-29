import { IUser } from "../models/user.model";
import UserRepository from "../repositories/user.repository";
import { ApiError } from "../utils/ApiError";
import { BcryptWrapper } from "../wrappers/bcrypt.wrapper";
import { StatusHelper } from "../helpers/status.helper";
import { ConstantHelper } from "../constants";
import { JwtWrapper } from "../wrappers/jwt.wrapper";

export default class UserService {
    userRepository: UserRepository;

    constructor(userRepository: UserRepository){
        this.userRepository = userRepository;
    }

    async registerUser(user: any): Promise<IUser> {
        const { firstName, lastName, username, email, password, role } = user;
    
        if (!firstName || !lastName || !username || !email || !password || !role) {
            throw new ApiError(StatusHelper.error400BadRequest, 'All fields are required');
        }
    
        const existingEmailUser = await this.userRepository.findUserByEmail(email);
        if (existingEmailUser) {
            throw new ApiError(StatusHelper.error409Conflict, 'User with this email already exists');
        }
    
        const existingUsernameUser = await this.userRepository.findUserByUsername(username);
        if (existingUsernameUser) {
            throw new ApiError(StatusHelper.error409Conflict, 'User with this username already exists');
        }
    
        const hashedPassword = await BcryptWrapper.hash(password);
    
        const newUser = await this.userRepository.addUser({
            name: { firstName, lastName },
            username,
            email,
            role,
            password: hashedPassword,
        });
    
        return newUser;
    }

    async loginUser(user: any){
        const {email, password} = user;

        if(!email || !password){
            throw new ApiError(StatusHelper.error400BadRequest, 'All fields are required, [email, password]');
        } 

        const existedUser = await this.userRepository.findUserByEmail(email);
        if(!existedUser){
            throw new ApiError(StatusHelper.error404NotFound, 'Invalid email, user with this email not found');
        }

        const isPasswordValid = await BcryptWrapper.compare(password, existedUser.password);
        if(!isPasswordValid){
            throw new ApiError(StatusHelper.error401Unauthorized, 'Invalid password');
        }

        const loggedInUser = await this.userRepository.findUserById(existedUser._id);

        const payload = {id : loggedInUser?._id}
        const secretKey = ConstantHelper.JWT_SECRET_KEY;
        const options = {expiresIn: '1h'}

        const token = JwtWrapper.sign(payload, secretKey, options);
        if(!token){
            throw new ApiError(StatusHelper.error400BadRequest, 'Something went wrong while generating jwt token');
        }

        return {token}
    }
    
}