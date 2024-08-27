jest.setTimeout(30000);
import mongoose from 'mongoose';
import request from 'supertest';
import { app } from '../app';
import { UserModel } from '../models/user.model';

describe('POST /signup', () => {

    beforeAll(async () => {
        await mongoose.connect('mongodb://localhost:27017/test', {
            serverSelectionTimeoutMS: 30000,
            socketTimeoutMS: 30000
        });
    });

    afterAll(async () => {
        await UserModel.deleteMany({}); // Clean up the test data
        await mongoose.connection.close();
    });

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
            .post('/api/v1/users/signup')
            .send({
                firstName: '',
                lastName: 'Doe',
                username: 'johndoe',
                email: 'johndoe@example.com',
                password: 'password123',
                role: 'user'
            });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('message', 'All fields are required');
    });

    it('should return 409 if the user already exists', async () => {

        await UserModel.deleteOne({username: 'johndoe'})

        await UserModel.create({
            name: { firstName: 'John', lastName: 'Doe' },
            username: 'johndoe',
            email: 'johndoe@example.com',
            password: 'hashedpassword123',
            role: 'user'
        });

        const response = await request(app)
            .post('/api/v1/users/signup')
            .send({
                firstName: 'Jane',
                lastName: 'Doe',
                username: 'johndoe',
                email: 'johndoe@example.com',
                password: 'password123',
                role: 'user'
            });

        expect(response.status).toBe(409);
        expect(response.body).toHaveProperty('message', 'User with email or username already exists');
    });
});
