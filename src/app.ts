import express, {Application, Request, Response} from 'express'
import { ConstantHelper } from './constants';
import bodyParser from 'body-parser';
import errorHandler from './middlewares/error-handler.middleware';
import cookieParser from 'cookie-parser'

const app : Application = express();
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.json())


import UserRoutes from './routes/user.routes'
app.use('/api/v1/users', UserRoutes);


app.get('/', (req: Request, res: Response) => {
    res.send(`<h1>Server is listening.</h1>`)
})


app.use(errorHandler) // middleware to handle api-errors
export {app}