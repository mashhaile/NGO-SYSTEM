// =====================================================
// RESTORE A BACKUP
// =====================================================
//
//   node scripts/restoreDatabase.js <backup-folder> --db <target-database>
//        [--uri-file .env.atlas] [--replace]
//
// Restores into <target-database> on the server from
// MONGO_URI (or --uri-file).
//
// Safety:
// - The target database name must be given explicitly.
// - If the target already has data, nothing is written
//   unless --replace is passed; --replace drops each
//   collection before restoring it.
// - Tip: restore into a NEW name first (e.g.
//   ngo_system_restore), check it, then switch.
//
// =====================================================

require("dotenv").config({ quiet: true });

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const mongoose = require("mongoose");

const resolveMongoUri = require("../utils/resolveMongoUri");

const { EJSON } = mongoose.mongo.BSON;


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


const main = async () => {

    const folder = process.argv[2];
    const target = argument("--db");
    const replace = process.argv.includes("--replace");

    if (!folder || folder.startsWith("--") || !target) {
        throw new Error("Usage: node scripts/restoreDatabase.js <backup-folder> --db <target-database> [--replace]");
    }

    const manifest =
        JSON.parse(fs.readFileSync(path.join(folder, "manifest.json"), "utf8"));

    await mongoose.connect(await resolveMongoUri(readUri()), { serverSelectionTimeoutMS: 45000 });

    const db = mongoose.connection.useDb(target, { useCache: false }).db;

    const existing =
        (await db.listCollections({}, { nameOnly: true }).toArray()).map(c => c.name);

    let hasData = false;
    for (const name of existing) {
        if (await db.collection(name).estimatedDocumentCount() > 0) {
            hasData = true;
            break;
        }
    }

    if (hasData && !replace) {
        throw new Error(`"${target}" already has data. Nothing was changed. Use a new database name, or --replace.`);
    }

    console.log(`Restoring backup of "${manifest.database}" (${manifest.createdAt}) into "${target}"`);

    for (const [name, expected] of Object.entries(manifest.collections)) {

        const docs =
            EJSON.parse(zlib.gunzipSync(fs.readFileSync(path.join(folder, `${name}.json.gz`))).toString("utf8"), { relaxed: false });

        if (existing.includes(name)) {
            await db.collection(name).drop();
        }

        if (docs.length) {
            await db.collection(name).insertMany(docs, { ordered: false });
        }

        const count = await db.collection(name).countDocuments();

        console.log(`  ${name}: ${count}${count === expected ? "" : `  (expected ${expected}!)`}`);

    }

    await mongoose.disconnect();

    console.log("Restore finished. Indexes are rebuilt by the app on its next start.");

};


main().catch(async (error) => {
    console.error("Restore failed:", error.message);
    await mongoose.disconnect().catch(() => {});
    process.exit(1);
});
