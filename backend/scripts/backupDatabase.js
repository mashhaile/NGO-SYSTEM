// =====================================================
// BACKUP THE DATABASE
// =====================================================
//
// Saves every collection to backups/<database>-<date>/ as
// gzipped Extended JSON (ObjectIds and dates are kept
// exactly), plus a manifest with document counts.
//
//   node scripts/backupDatabase.js                      (MONGO_URI from .env)
//   node scripts/backupDatabase.js --uri-file .env.atlas --db ngo_system   (live)
//
// Read-only: it never changes the database.
// The backups/ folder is git-ignored; copy important
// backups somewhere safe (USB, cloud drive).
//
// =====================================================

require("dotenv").config({ quiet: true });

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const mongoose = require("mongoose");

const {
    connectForScript
} = require("../utils/scriptConnection");

const { EJSON } = mongoose.mongo.BSON;




const main = async () => {

    // --db picks the database when the connection string has
    // none (Atlas strings often end in "/", which means "test")

    const db = (await connectForScript()).db;

    const stamp =
        new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);

    const folder =
        path.join(__dirname, "..", "backups", `${db.databaseName}-${stamp}`);

    fs.mkdirSync(folder, { recursive: true });

    const collections =
        (await db.listCollections({}, { nameOnly: true }).toArray())
            .map(c => c.name)
            .filter(name => !name.startsWith("system."))
            .sort();

    if (!collections.length) {
        fs.rmSync(folder, { recursive: true, force: true });
        throw new Error(`Database "${db.databaseName}" is empty or does not exist. Pass --db <name> (live: --db ngo_system).`);
    }

    const manifest = {
        database: db.databaseName,
        createdAt: new Date().toISOString(),
        collections: {}
    };

    for (const name of collections) {

        const docs =
            await db.collection(name).find({}).toArray();

        fs.writeFileSync(
            path.join(folder, `${name}.json.gz`),
            zlib.gzipSync(EJSON.stringify(docs, { relaxed: false }))
        );

        manifest.collections[name] = docs.length;

        console.log(`  ${name}: ${docs.length}`);

    }

    fs.writeFileSync(
        path.join(folder, "manifest.json"),
        JSON.stringify(manifest, null, 2)
    );

    await mongoose.disconnect();

    console.log(`Backup of "${db.databaseName}" saved to ${folder}`);

};


main().catch(async (error) => {
    console.error("Backup failed:", error.message);
    await mongoose.disconnect().catch(() => {});
    process.exit(1);
});
