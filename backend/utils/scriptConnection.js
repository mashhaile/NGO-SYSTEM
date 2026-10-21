const fs = require("fs");
const path = require("path");

const mongoose = require("mongoose");

const resolveMongoUri = require("./resolveMongoUri");


// =====================================================
// DATABASE CONNECTION FOR COMMAND-LINE SCRIPTS
// =====================================================
//
// Options shared by the maintenance scripts:
//
//   (default)               MONGO_URI from .env / environment
//   --uri-file <file>       a file holding the connection string
//                           (e.g. .env.atlas for the live database)
//   --db <name>             database to use when the string has
//                           none (live: ngo_system)
//
// mongodb+srv:// addresses are resolved through public DNS,
// so scripts work on networks whose DNS blocks SRV lookups.
//
// =====================================================

const argument = (name) => {
    const index = process.argv.indexOf(name);
    return index >= 0 ? process.argv[index + 1] : null;
};


const readUri = () => {

    const file = argument("--uri-file");

    if (!file) {
        return process.env.MONGO_URI;
    }

    const text = fs.readFileSync(path.resolve(file), "utf8").trim();
    const line = text.split(/\r?\n/).find(l => /mongodb(\+srv)?:\/\//.test(l)) || "";

    return line.replace(/^\s*MONGO_URI\s*=\s*/, "").trim();

};


// Connects the default mongoose connection (so models work)
// to the chosen database.

const connectForScript = async () => {

    const uri = readUri();

    if (!uri) {
        throw new Error("No connection string (set MONGO_URI or pass --uri-file).");
    }

    await mongoose.connect(await resolveMongoUri(uri), {
        serverSelectionTimeoutMS: 45000,
        ...(argument("--db") ? { dbName: argument("--db") } : {})
    });

    return mongoose.connection;

};


module.exports = {
    argument,
    connectForScript
};
