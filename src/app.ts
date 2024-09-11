import express, {Application, Request, Response} from 'express'
import { ConstantHelper } from './constants';
import bodyParser from 'body-parser';
import errorHandler from './middlewares/error-handler.middleware';
import cookieParser from 'cookie-parser'
// import {UserRouter }from './routes/user.routes';
import UserController from './controllers/user.controller';
import UserService from './services/user.service';
import UserRepository from './repositories/user.repository';
import {loggerMiddleware} from './middlewares/logger.middleware'

const app : Application = express();
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.json())
app.use(loggerMiddleware)


import UserRoutes from './routes/user.routes'
// app.use('/api/v1/users', UserRoutes);
// console.log(UserRouter);

// const userRepository = new UserRepository();
// const userService = new UserService(userRepository);
// const userController = new UserController(userService);
// const userRoutes = new UserRouter()
// console.log('user routes err ',userRoutes);
// 
app.use('/api/v1/users', UserRoutes)


app.get('/', (req: Request, res: Response) => {
    res.send(`<h1>Server is listening.</h1>`)
})


app.use(errorHandler) // middleware to handle api-errors
export {app}