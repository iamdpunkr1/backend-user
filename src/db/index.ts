import { MongoClient, Db, Collection } from 'mongodb';
import { configDotenv } from 'dotenv';
// import User from '../models/User';

configDotenv({
    path: "./env"
});

const uri: string = process.env.MONGO_URI || '';
const dbName: string = process.env.DB || '';

class MongoBot {
    client: MongoClient;
    db: Db;
    Users: Collection<any>;

    constructor() {
        this.client = new MongoClient(uri);
        this.db = {} as Db; // Initialize db property to avoid TypeScript errors
        this.Users = {} as Collection<any>; 
    }

    async init(): Promise<void> {
        try {
            await this.client.connect();
            console.log('connected');
            this.db = this.client.db(dbName);
            this.Users = this.db.collection('users');
        } catch (error) {
            console.error('Error connecting to MongoDB:', error);
            throw error; // Re-throw error to handle it at the caller level
        }
    }
}

export default new MongoBot();
