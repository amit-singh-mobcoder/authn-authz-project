import { ObjectId } from "mongoose";
import { IUser, UserModel } from "../models/user.model";

export default class UserRepository {

  async addUser(user: Partial<IUser>): Promise<IUser> {
    const newUser = new UserModel(user);
    return await newUser.save();
  }

  async findUserByEmail(email: string): Promise<IUser | null> {
    const existedUser = await UserModel.findOne({email});
    return existedUser;
  }

  async findUserByUsername(username: string): Promise<IUser| null> {
    const existedUser = await UserModel.findOne({username});
    return existedUser;
  }

  async findUserById(id: any): Promise<IUser | null> {
    const user = await UserModel.findById(id);
    return user;
  }

  async updateUserPasswordById(id: ObjectId ,newPassword: string): Promise<IUser|null>{
    const updatedUser = await UserModel.findByIdAndUpdate(id, {password: newPassword});
    return updatedUser;
  }

  async deleteUserById(id: ObjectId){
    await UserModel.findByIdAndDelete(id);
  }

  async countTotalUsers(){
    return await UserModel.countDocuments();
  }

  async allUsersWithPagination(page: number, perPage: number){
    const users = await UserModel.find().skip((page - 1) * perPage).limit(perPage).exec();
    return users;
  }
}