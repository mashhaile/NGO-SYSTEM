// =====================================================
// INITIATE SINGLE-NODE REPLICA SET
// =====================================================
//
// Called by enable-mongo-replica-set.ps1 after mongod
// has been restarted with replication.replSetName.
// Safe to run again: does nothing if already initiated.
//
// Usage (from backend/):
//
//     node scripts/initReplicaSet.js [replSetName] [host:port]
//
// =====================================================

const { MongoClient } = require("mongodb");


const REPL_SET =
    process.argv[2] || "rs0";

const HOST =
    process.argv[3] || "127.0.0.1:27017";


const sleep = (ms) =>
    new Promise(resolve =>
        setTimeout(resolve, ms)
    );


const main = async () => {

    const client =
        new MongoClient(
            `mongodb://${HOST}/?directConnection=true`
        );

    await client.connect();

    const admin =
        client.db("admin");

    try {

        const status =
            await admin.command({
                replSetGetStatus: 1
            });

        console.log(
            `Replica set "${status.set}" is already initiated.`
        );

    }
    catch (error) {

        // 94 = NotYetInitialized

        if (error.code !== 94) {
            throw error;
        }

        await admin.command({
            replSetInitiate: {
                _id: REPL_SET,
                members: [
                    {
                        _id: 0,
                        host: HOST
                    }
                ]
            }
        });

        console.log(
            `Replica set "${REPL_SET}" initiated.`
        );

    }


    // Wait until this node is primary (accepts writes).

    for (let attempt = 0; attempt < 30; attempt++) {

        const hello =
            await admin.command({
                hello: 1
            });

        if (hello.isWritablePrimary) {

            console.log(
                "✅ Node is primary. Transactions are available."
            );

            await client.close();

            return;

        }

        await sleep(1000);

    }

    await client.close();

    throw new Error(
        "Node did not become primary within 30 seconds."
    );

};


main().catch(error => {

    console.error(
        "❌ Replica set setup failed:",
        error.message
    );

    process.exitCode = 1;

});
