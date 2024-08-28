import { app } from "./app";
import MongoDbConnector from './connectors/mongodb.connector'
import { ConstantHelper } from "./constants";

MongoDbConnector.connect()
.then(() => {
    app.listen(ConstantHelper.APP_PORT, () => {
        console.log(`Server listening at http://localhost:${ConstantHelper.APP_PORT}`);
    })
})