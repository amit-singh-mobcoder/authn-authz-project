jest.setTimeout(3000)
import mongoose from "mongoose"
import request from 'supertest'
import { app } from "../app"
import { UserModel } from "../models/user.model"


describe('POST /login', ()=> {

    beforeAll(async()=>{
        await mongoose.connect('mongodb://localhost:27017/test', {
            serverSelectionTimeoutMS: 30000,
            socketTimeoutMS: 30000
        });
    })

    afterAll(async()=>{
        await UserModel.deleteMany({})
        await mongoose.connection.close();
    })

    it('should register a new user successfully', async () => {
        const response = await request(app)
            .post('/api/v1/users/signup')
            .send({
                firstName: 'John',
                lastName: 'Doe',
                username: 'johndoe',
                email: 'johndoe@example.com',
                password: 'password123',
                role: 'user'
            });

        expect(response.status).toBe(201);
        expect(response.body).toHaveProperty('data.username', 'johndoe');
        expect(response.body).toHaveProperty('message', 'User registered successfully');
    });

    it('should return 400 if any required field is missing', async () => {
        const response = await request(app)
        .post('/api/v1/users/login')
        .send({
            username: "",
            password: "password123"
        })
        expect(response.status).toBe(400)
        expect(response.body).toHaveProperty('message','username or email is required')
    });

    it('should return 404 if user not found with provided username or email', async () => {
        const response = await request(app)
        .post('/api/v1/users/login')
        .send({
            username:'johndoe1234',
            email: "johndoe@gmail.com",
            password: "password123"
        })
        expect(response.status).toBe(404)
        expect(response.body).toHaveProperty('message', 'User with email or username does not exist')
    });

    it('should return 401 if user provide valid username or email and invalid password', async () => {
        const response = await request(app)
        .post('/api/v1/users/login')
        .send({
            username:'johndoe',
            email: "johndoe@example.com",
            password:"1234"
        })
        expect(response.status).toBe(401)
        expect(response.body).toHaveProperty('message','Invalid user credential')
    })

    it('should user login successfully', async () => {
        const response = await request(app)
        .post('/api/v1/users/login')
        .send({
            username: 'johndoe',
            password: 'password123'
        })

        expect(response.status).toBe(200)
        expect(response.body).toHaveProperty('message','user login successfully')
    });

})