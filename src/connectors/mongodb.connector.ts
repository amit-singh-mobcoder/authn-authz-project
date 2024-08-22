import mongoose from "mongoose";
import { ConstantHelper } from "../constants";

class MongoDbConnector {
    public uri: string;

    constructor(uri: string){
        if(!uri) {
            throw new Error("MongoDb uri us missing.")
        }
        this.uri = uri;
    }
    
    async connect(){
        try {
            const connectionInstance = await mongoose.connect(`${this.uri}/${ConstantHelper.DB_NAME}`);
            console.log(`MongoDb connection successfull DB-HOST : ${connectionInstance.connection.host}`);
        } catch (error) {
            console.error('MongoDb connection failed !! Error : ',error);
            process.exit(1);
        }
    }
}

export default new MongoDbConnector(ConstantHelper.uri!);