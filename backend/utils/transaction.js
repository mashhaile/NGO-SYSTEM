const mongoose = require("mongoose");


// =====================================================
// DATABASE TRANSACTIONS
// =====================================================
//
// MongoDB transactions need a replica set (MongoDB
// Atlas always is one; a local server must be started
// with a replSetName, see
// scripts/enable-mongo-replica-set.ps1).
//
// runInTransaction(work) runs work(session) inside a
// transaction when the server supports it, retrying
// on transient errors. On a standalone server it runs
// work(null) once and logs a warning, so callers must
// still handle partial failure themselves (see
// serviceDeliveryService for the compensation used).
//
// =====================================================

let transactionSupport = null;

let warned = false;


const supportsTransactions = async () => {

    if (transactionSupport !== null) {
        return transactionSupport;
    }

    try {

        const hello =
            await mongoose.connection.db
                .admin()
                .command({
                    hello: 1
                });

        transactionSupport =
            Boolean(
                hello.setName ||
                hello.msg === "isdbgrid"
            );

    }
    catch {

        transactionSupport = false;

    }

    return transactionSupport;

};


const runInTransaction = async (work) => {

    if (await supportsTransactions()) {

        return mongoose.connection.transaction(
            session => work(session)
        );

    }

    if (!warned) {

        warned = true;

        console.warn(
            "⚠️  MongoDB is not a replica set: multi-document saves run without a transaction. " +
            "Run backend/scripts/enable-mongo-replica-set.ps1 (local) or use a replica set in production."
        );

    }

    return work(null);

};


module.exports = {
    supportsTransactions,
    runInTransaction
};
