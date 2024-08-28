import { IUser, UserModel } from "../models/user.model";
import { FilterQuery } from "mongoose";

export class UserRepository {

  static async findOne(condition: FilterQuery<IUser>): Promise<IUser | null> {
    const item = await UserModel.findOne(condition).exec();
    return item;
  }

  static async create(data: Partial<IUser>): Promise<IUser> {
    const user = await UserModel.create(data);
    return user;
  }

  static async findById(id: any): Promise<IUser | null> {
    const user = await UserModel.findById(id).select('-password').exec();
    return user;
  }

  static async findByIdAndUpdate(id: any): Promise<IUser | null> {
    const updatedUser = await UserModel.findByIdAndUpdate(id);
    return updatedUser;
  }

  static async findByIdAndDelete(id: any): Promise<IUser | null> {
    const deletedUser = await UserModel.findByIdAndDelete(id);
    return deletedUser;
  }
}