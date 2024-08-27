import mongoose from "mongoose";
import { ConstantHelper, mongooseOptions } from "../constants";

class MongoDbConnector {
    public uri: string;
    private _mongooseOptions: object = mongooseOptions;

    constructor(uri: string){
        if(!uri) {
            throw new Error("MongoDb uri us missing.")
        }
        this.uri = uri;
    }
    
    async connect(){
        try {
            const connectionInstance = await mongoose.connect(`${this.uri}/${ConstantHelper.DB_NAME}`, this._mongooseOptions);
            console.log(`MongoDb connection successfull DB-HOST : ${connectionInstance.connection.host}`);
        } catch (error) {
            console.error('MongoDb connection failed !! Error : ',error);
            process.exit(1);
        }
    }
}

export default new MongoDbConnector(ConstantHelper.uri!);