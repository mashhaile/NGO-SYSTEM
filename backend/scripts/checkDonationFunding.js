// =====================================================
// CHECK DONATION FUNDING (read-only)
// =====================================================
//
// Lists what breaks the donation funding rules (see
// services/donationFunding.js), so it can be corrected in
// the screens before those records are edited again:
//
//   - a restricted donation paying for work it is not for
//     (another project / activity than its own)
//   - a cancelled donation still paying for something
//   - a donation using more than its amount (service
//     deliveries + submitted / approved expenses)
//   - a charge in a currency the donation cannot be
//     compared in
//
//   node scripts/checkDonationFunding.js
//   node scripts/checkDonationFunding.js --uri-file .env.atlas --db ngo_system
//
// Changes nothing.
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const { connectForScript } = require("../utils/scriptConnection");

const fs = require("fs");
const path = require("path");
for (const file of fs.readdirSync(path.join(__dirname, "../models"))) {
    if (file.endsWith(".js")) { try { require(path.join(__dirname, "../models", file)); } catch (error) { /* duplicate */ } }
}

const donationFunding = require("../services/donationFunding");


const main = async () => {

    await connectForScript();

    const db = mongoose.connection.db;

    console.log(`Database: ${mongoose.connection.name} (read-only)`);

    const donations = await db.collection("donations").find({ isDeleted: { $ne: true } }).toArray();
    const problems = [];

    for (const donation of donations) {

        const name = `${donation.donationCode} ${donation.title}`;
        const issues = [];
        const currency = String(donation.currency || "ETB").toUpperCase();

        const deliveries = await db.collection("servicedeliveries").find({
            organization: donation.organization,
            isDeleted: { $ne: true },
            status: { $ne: "Cancelled" },
            $or: [{ "items.donation": donation._id }, { donation: donation._id }]
        }).toArray();

        for (const delivery of deliveries) {
            for (const item of delivery.items || []) {
                const paid = String(item.donation || "") === String(donation._id) || (!item.donation && String(delivery.donation || "") === String(donation._id));
                if (!paid) continue;
                try {
                    donationFunding.assertMayPayFor(donation, delivery, "This delivery");
                }
                catch (error) {
                    issues.push(`${delivery.deliveryNumber}: ${error.message}`);
                }
                if (donationFunding.itemInCurrency(item, currency) === null) {
                    issues.push(`${delivery.deliveryNumber}: an item recorded in ${item.currency || "ETB"} charged to a ${currency} donation`);
                }
            }
        }

        const expenses = await db.collection("expenses").find({
            organization: donation.organization,
            isDeleted: { $ne: true },
            donation: donation._id,
            status: { $in: ["Submitted", "Approved"] }
        }).toArray();

        for (const expense of expenses) {
            try {
                donationFunding.assertMayPayFor(donation, expense, "This expense");
            }
            catch (error) {
                issues.push(`${expense.expenseCode}: ${error.message}`);
            }
            if (donationFunding.expenseInCurrency(expense, currency) === null) {
                issues.push(`${expense.expenseCode}: recorded in ${expense.currency} (budget ${expense.budgetCurrency}), the donation is in ${currency}`);
            }
        }

        if (currency !== "ETB" && donation.status === "Received" && !(Number(donation.receivedRate) > 0)) {
            issues.push(`received in ${currency} with no exchange rate for that day: enter it (edit the donation), or ETB totals leave it out`);
        }

        const use = await donationFunding.donationUse(donation, donation.organization);
        if (use.left < -0.01) {
            issues.push(`uses ${currency} ${use.used.toLocaleString("en-US")} (deliveries ${use.byDeliveries.toLocaleString("en-US")} + expenses ${use.byExpenses.toLocaleString("en-US")}) of ${use.amount.toLocaleString("en-US")}: ${(-use.left).toLocaleString("en-US")} over`);
        }

        if (issues.length) problems.push({ name, issues: [...new Set(issues)] });

    }

    if (!problems.length) {
        console.log(`\nAll ${donations.length} donations follow the funding rules.`);
        return;
    }

    console.log(`\n${problems.length} of ${donations.length} donations break the funding rules:`);
    for (const problem of problems) {
        console.log(`  ${problem.name}`);
        for (const issue of problem.issues) console.log(`    - ${issue}`);
    }

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
