jest.setTimeout(30000)
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

    // TEST CASE 1 
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

    // TEST CASE 2
    it('should return 400 if any required field is missing', async () => {
        const response = await request(app)
        .post('/api/v1/users/login')
        .send({
            username: "",
            password: "password123"
        })
        expect(response.status).toBe(400)
        expect(response.body).toHaveProperty('message','All fields are required, [email, password]')
    });

    // TEST CASE 3
    it('should return 404 if user not found with provided email', async () => {
        const response = await request(app)
        .post('/api/v1/users/login')
        .send({
            email: "johndoe@gmail.com",
            password: "password123"
        })
        expect(response.status).toBe(404)
        expect(response.body).toHaveProperty('message', 'Invalid email, user with this email not found')
    });

    // TEST CASE 4
    it('should return 401 if user provide valid email and invalid password', async () => {
        const response = await request(app)
        .post('/api/v1/users/login')
        .send({
            email: "johndoe@example.com",
            password:"1234"
        })
        expect(response.status).toBe(401)
        expect(response.body).toHaveProperty('message','Invalid password')
    })

    // TEST CASE 5
    it('should user login successfully', async () => {
        const response = await request(app)
        .post('/api/v1/users/login')
        .send({
            email: "johndoe@example.com",
            password: 'password123'
        })

        expect(response.status).toBe(200)
        expect(response.body).toHaveProperty('message','User login successfully')
    });

})