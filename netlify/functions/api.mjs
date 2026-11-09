import serverless from "serverless-http";
import app from "../../backend/src/server.js";

export const handler = serverless(app);
