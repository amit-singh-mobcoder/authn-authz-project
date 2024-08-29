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
}