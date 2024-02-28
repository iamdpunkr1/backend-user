import express from "express";
import cors from "cors";
import mongo from "./db/index";
import router from "./routes/userRoutes";
import cookieParser from "cookie-parser";
// import mongo from "./utils/mongo";

const app = express();


app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"))
app.use(cors({
    origin:"http://localhost:5173",
    credentials:true
}))

// let db:any;

async function startServer() {
    try {
        // db = await connectToMongoDB();
        await mongo.init();
        app.use("/", router )
        app.listen(5000, () => console.log("Server running on localhost:5000"));
    } catch (error) {
        console.error('Error starting server:', error);
    }
}

// Start the server
startServer();
// export default db;
