import { MongoClient } from 'mongodb';
import { configDotenv } from 'dotenv';
configDotenv({
    path:"./env"
})

const uri = process.env.MONGO_URI;
const dbName = process.env.DB;


async function connectToMongoDB() {
    try {
        const client = new MongoClient(uri);
        await client.connect();
        console.log('Connected to MongoDB Atlas');
        return client.db(dbName);
    } catch (error) {
        console.error('Error connecting to MongoDB Atlas:', error);
        throw error;
    }
}

export default connectToMongoDB;