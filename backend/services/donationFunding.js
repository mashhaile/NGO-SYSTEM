// =====================================================
// DONATION FUNDING: WHAT A DONATION MAY PAY FOR, AND
// WHAT IT HAS LEFT
// =====================================================
//
// Used by service deliveries (items charged to a donation)
// and by expenses (charged to a donation):
//
// MAY PAY FOR
//   - a cancelled donation pays for nothing
//   - a RESTRICTED donation pays only for what it was given
//     for: its activity run, else its activity, else its
//     project, else its program (any project of it). With
//     none of these set, it is restricted by purpose only
//     (its description) and is not limited here.
//   - an UNRESTRICTED donation pays for any work of the
//     organization (pooled funding).
//
// WHAT IT HAS LEFT (in the donation's own currency)
//   amount
//   - delivered service items charged to it
//   - submitted and approved expenses charged to it
//   (a record being edited is left out, so it is never
//   counted twice)
//
// Amounts in another currency are only used when they are
// recorded in the donation's currency: an expense in that
// currency, an expense whose budget is in it, or a service
// item recorded in it (its original currency). Anything
// else cannot be compared and is refused when charged.
//
// =====================================================

const mongoose = require("mongoose");

const Donation = require("../models/donation");
const ServiceDelivery = require("../models/ServiceDelivery");
const Expense = require("../models/Expense");
const ApiError = require("../utils/apiError");


const toId = (value) =>
    value && typeof value === "object" ? String(value._id || value) : value ? String(value) : "";

const toNumber = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : 0;
};

const roundMoney = (value) => Math.round(toNumber(value) * 100) / 100;

const money = (amount, currency) =>
    `${currency} ${roundMoney(amount).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

const BASE_CURRENCY = "ETB";

const label = (donation) => [donation.donationCode, donation.title].filter(Boolean).join(" ");


// ---------- may this donation pay for that work? ----------

const scopeOf = (donation) =>
    donation.activityRun ? { level: "activity run", key: "activityRun", id: toId(donation.activityRun) }
        : donation.activity ? { level: "activity", key: "activity", id: toId(donation.activity) }
            : donation.project ? { level: "project", key: "project", id: toId(donation.project) }
                : donation.program ? { level: "program", key: "program", id: toId(donation.program) }
                    : null;

// work = { program, project, activity, activityRun } of the delivery / expense
const assertMayPayFor = (donation, work, what = "This") => {

    if (donation.status === "Cancelled") {
        throw new ApiError(`${label(donation)} is cancelled; it cannot pay for anything. Choose another donation.`, 400);
    }

    if (String(donation.fundingRestriction || "Unrestricted") !== "Restricted") {
        return;
    }

    const scope = scopeOf(donation);

    if (!scope) {
        return;
    }

    if (toId(work?.[scope.key]) !== scope.id) {
        throw new ApiError(
            `${label(donation)} is restricted to its ${scope.level}; ${what.toLowerCase()} is for another ${scope.level}. Choose a donation for this work, or an unrestricted one.`,
            400
        );
    }

};


// ---------- what a delivery item / expense is worth in a donation's currency ----------

// a service item: its ETB value, or its original amount when recorded in the donation's currency
const itemInCurrency = (item, currency) => {
    const original = String(item.currency || BASE_CURRENCY).toUpperCase();
    if (original === currency) {
        return original === BASE_CURRENCY
            ? toNumber(item.totalCost)
            : toNumber(item.originalTotal ?? toNumber(item.quantity) * toNumber(item.originalUnitCost));
    }
    if (currency === BASE_CURRENCY) return toNumber(item.totalCost);
    return null;
};

const expenseInCurrency = (expense, currency) => {
    if (String(expense.currency || "").toUpperCase() === currency) return toNumber(expense.amount);
    if (String(expense.budgetCurrency || "").toUpperCase() === currency) return toNumber(expense.budgetAmount);
    return null;
};


// ---------- what is used and left ----------

const donationUse = async (donationOrId, organizationId, { excludeDeliveryId = null, excludeExpenseId = null, session = null } = {}) => {

    const donation =
        donationOrId && donationOrId._id && donationOrId.amount !== undefined
            ? donationOrId
            : await Donation.findOne({ _id: donationOrId, organization: organizationId, isDeleted: { $ne: true } }).session(session).lean();

    if (!donation) throw new ApiError("Donation not found.", 404);

    const currency = String(donation.currency || BASE_CURRENCY).toUpperCase();
    const id = toId(donation._id);

    const deliveries =
        await ServiceDelivery.find({
            organization: donation.organization || organizationId,
            isDeleted: false,
            status: { $ne: "Cancelled" },
            ...(excludeDeliveryId ? { _id: { $ne: excludeDeliveryId } } : {}),
            $or: [{ "items.donation": donation._id }, { donation: donation._id }]
        })
            .select("deliveryNumber donation items")
            .session(session)
            .lean();

    let byDeliveries = 0;
    for (const delivery of deliveries) {
        for (const item of delivery.items || []) {
            if (toId(item.donation) !== id && !(!item.donation && toId(delivery.donation) === id)) continue;
            byDeliveries += toNumber(itemInCurrency(item, currency));
        }
    }

    const expenses =
        await Expense.find({
            organization: donation.organization || organizationId,
            isDeleted: { $ne: true },
            donation: donation._id,
            status: { $in: ["Submitted", "Approved"] },
            ...(excludeExpenseId ? { _id: { $ne: excludeExpenseId } } : {})
        })
            .select("amount currency budgetAmount budgetCurrency status")
            .session(session)
            .lean();

    let byExpenses = 0;
    for (const expense of expenses) byExpenses += toNumber(expenseInCurrency(expense, currency));

    const amount = roundMoney(donation.amount);
    const used = roundMoney(byDeliveries + byExpenses);

    return {
        donation,
        currency,
        amount,
        status: donation.status,
        byDeliveries: roundMoney(byDeliveries),
        byExpenses: roundMoney(byExpenses),
        used,
        left: roundMoney(amount - used)
    };

};


// ---------- charge a donation (check it may pay and has enough) ----------

const assertCanCharge = async ({ donationId, organizationId, work, charge, chargeCurrency, what = "This", excludeDeliveryId = null, excludeExpenseId = null, session = null }) => {

    const use = await donationUse(donationId, organizationId, { excludeDeliveryId, excludeExpenseId, session });
    const { donation, currency } = use;

    assertMayPayFor(donation, work, what);

    if (charge === null || charge === undefined) {
        throw new ApiError(
            `${label(donation)} is in ${currency}; ${what.toLowerCase()} is recorded in ${chargeCurrency || BASE_CURRENCY}. Record it in ${currency}, or charge a donation in ${chargeCurrency || BASE_CURRENCY}.`,
            400
        );
    }

    if (roundMoney(charge) > use.left + 0.01) {
        throw new ApiError(
            `${label(donation)} has ${money(Math.max(use.left, 0), currency)} left (${money(use.amount, currency)} ${donation.status === "Pledged" ? "pledged" : "received"}; ${money(use.byDeliveries, currency)} in service deliveries and ${money(use.byExpenses, currency)} in expenses so far), but ${what.toLowerCase()} needs ${money(charge, currency)}.`,
            400,
            [{ field: "donation", code: "DONATION_BALANCE", left: use.left, needed: roundMoney(charge), currency }]
        );
    }

    return use;

};


// Serialize charges to one donation inside a transaction:
// two saves at the same moment cannot both use the last of it
const lockDonation = (donationId, session) =>
    session
        ? Donation.updateOne({ _id: donationId }, { $inc: { chargeVersion: 1 } }, { session, strict: false })
        : Promise.resolve();


module.exports = {
    BASE_CURRENCY,
    assertMayPayFor,
    assertCanCharge,
    donationUse,
    itemInCurrency,
    expenseInCurrency,
    lockDonation,
    isObjectId: (value) => mongoose.isValidObjectId(value)
};
