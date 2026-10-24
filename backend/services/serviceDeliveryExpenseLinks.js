// =====================================================
// SERVICE ITEMS BOUGHT WITH AN EXPENSE
// =====================================================
//
// Kits bought with EXP-000123 (75,000) and then given out
// in a delivery (75,000) are the same money. The delivery
// item is linked to the expense (paidByExpense), so the
// donation is charged once, by the expense (see
// donationFunding). The delivery still shows where the
// kits went.
//
// Here:
//   checkLinks     the link is valid (same donation and
//                  project; the items bought with one
//                  expense cost no more than it)
//   options        the expenses an item may have been bought
//                  with, the close ones first (suggestion)
//   refusalHint    "link it to EXP-...", for the "not enough
//                  left" refusal
//   review         delivery items and expenses on the same
//                  donation with about the same amount and
//                  no link: possible double counting
//   setLink        link / mark as separate from the review
//
// =====================================================

const mongoose = require("mongoose");

const ServiceDelivery = require("../models/ServiceDelivery");
const Expense = require("../models/Expense");
const Donation = require("../models/donation");
const ApiError = require("../utils/apiError");

const funding = require("./donationFunding");

const { toId, money, label } = funding;

// "about the same amount": within 15%
const CLOSE = 0.15;

const LINKABLE_STATUS = ["Draft", "Submitted", "Approved", "Returned"];

const round = (value) => Math.round(Number(value || 0) * 100) / 100;

const itemName = (item, index) =>
    item?.serviceType?.value || item?.serviceType?.name || `Service item ${index + 1}`;


// What items (other deliveries + these) bought with each expense cost, in the expense's currency
const linkedCost = async (expenses, organizationId, { excludeDeliveryId = null, extraItems = [] } = {}) => {

    const ids = expenses.map(expense => expense._id);
    const byExpense = new Map(expenses.map(expense => [toId(expense._id), 0]));

    if (!ids.length) return byExpense;

    const deliveries =
        await ServiceDelivery.find({
            organization: organizationId,
            isDeleted: false,
            status: { $ne: "Cancelled" },
            "items.paidByExpense": { $in: ids },
            ...(excludeDeliveryId ? { _id: { $ne: excludeDeliveryId } } : {})
        })
            .select("items")
            .lean();

    const currencyOf = new Map(expenses.map(expense => [toId(expense._id), String(expense.currency || funding.BASE_CURRENCY).toUpperCase()]));

    const add = (item) => {
        const key = toId(item.paidByExpense);
        if (!byExpense.has(key)) return;
        byExpense.set(key, byExpense.get(key) + Number(funding.itemInCurrency(item, currencyOf.get(key)) || 0));
    };

    for (const delivery of deliveries) for (const item of delivery.items || []) if (item.paidByExpense) add(item);
    for (const item of extraItems) if (item.paidByExpense) add(item);

    return byExpense;

};


// ---------- the link is valid ----------

const checkLinks = async (items, organizationId, { project = null, excludeDeliveryId = null } = {}) => {

    const linked = (items || []).filter(item => item?.paidByExpense);
    if (!linked.length) return;

    const expenses =
        await Expense.find({
            _id: { $in: linked.map(item => item.paidByExpense).filter(id => mongoose.isValidObjectId(id)) },
            organization: organizationId,
            isDeleted: { $ne: true }
        })
            .select("expenseCode description amount currency budgetAmount budgetCurrency donation project status")
            .lean();

    const byId = new Map(expenses.map(expense => [toId(expense._id), expense]));

    for (const item of linked) {

        const expense = byId.get(toId(item.paidByExpense));

        if (!expense) {
            throw new ApiError("The expense these items were bought with was not found. Choose it again, or remove the link.", 400);
        }

        if (expense.status === "Voided") {
            throw new ApiError(`${expense.expenseCode} is voided, so it did not pay for these items. Remove the link, or choose the expense that paid.`, 400);
        }

        if (project && expense.project && toId(expense.project) !== toId(project)) {
            throw new ApiError(`${expense.expenseCode} is for another project than this delivery. Items can only be linked to an expense of the same project.`, 400);
        }

        if (item.donation && expense.donation && toId(item.donation) !== toId(expense.donation)) {
            const other = await Donation.findById(expense.donation).select("donationCode title").lean();
            throw new ApiError(`${expense.expenseCode} was paid from ${other ? label(other) : "another donation"}; this item is charged to another one. Charge the item to the same donation, or remove the link.`, 400);
        }

        // bought with the expense: paid from its donation
        if (!item.donation && expense.donation) {
            item.donation = expense.donation;
            if (!item.donor) {
                const donation = await Donation.findById(expense.donation).select("donor").lean();
                item.donor = donation?.donor || null;
            }
        }

        item.separateFromExpenses = (item.separateFromExpenses || []).filter(id => toId(id) !== toId(expense._id));

    }

    // the items bought with one expense cost no more than it
    const cost = await linkedCost(expenses, organizationId, { excludeDeliveryId, extraItems: linked });

    for (const expense of expenses) {
        const currency = String(expense.currency || funding.BASE_CURRENCY).toUpperCase();
        const total = cost.get(toId(expense._id)) || 0;
        if (round(total) > Number(expense.amount || 0) + 0.01) {
            throw new ApiError(
                `The items bought with ${expense.expenseCode} come to ${money(total, currency)}, more than the expense (${money(expense.amount, currency)}). Check the link, the quantities or the prices.`,
                400
            );
        }
    }

};


// ---------- the expenses an item may have been bought with ----------

const options = async ({ organizationId, donation: donationId, project = null, amount = 0, excludeDeliveryId = null }) => {

    if (!mongoose.isValidObjectId(donationId)) return [];

    const donation = await Donation.findOne({ _id: donationId, organization: organizationId, isDeleted: { $ne: true } }).select("currency donationCode title").lean();
    if (!donation) return [];

    const currency = String(donation.currency || funding.BASE_CURRENCY).toUpperCase();

    const expenses =
        await Expense.find({
            organization: organizationId,
            isDeleted: { $ne: true },
            donation: donation._id,
            status: { $in: LINKABLE_STATUS },
            ...(project && mongoose.isValidObjectId(project) ? { project } : {})
        })
            .select("expenseCode description amount currency budgetAmount budgetCurrency expenseDate status project")
            .sort({ expenseDate: -1 })
            .lean();

    const cost = await linkedCost(expenses, organizationId, { excludeDeliveryId });
    const wanted = Number(amount || 0);

    return expenses
        .map(expense => {
            const remaining = round(Number(expense.amount || 0) - (cost.get(toId(expense._id)) || 0));
            const inDonation = funding.expenseInCurrency(expense, currency);
            const remainingInDonation =
                inDonation === null || !Number(expense.amount)
                    ? null
                    : round(inDonation * (remaining / Number(expense.amount)));
            const counted = funding.COUNTED_EXPENSE_STATUS.includes(expense.status);
            return {
                _id: expense._id,
                expenseCode: expense.expenseCode,
                description: expense.description,
                expenseDate: expense.expenseDate,
                status: expense.status,
                amount: expense.amount,
                currency: expense.currency,
                remaining,
                remainingInDonation,
                donationCurrency: currency,
                counted,
                close:
                    counted &&
                    wanted > 0 &&
                    remainingInDonation !== null &&
                    Math.abs(remainingInDonation - wanted) <= wanted * CLOSE
            };
        })
        .filter(option => option.remaining > 0.009)
        .sort((a, b) => Number(b.close) - Number(a.close));

};


// ---------- "not enough left": name the expenses it may have been bought with ----------

const refusalHint = async (donationId, organizationId, { project = null, excludeDeliveryId = null } = {}) => {

    const found = (await options({ organizationId, donation: donationId, project, excludeDeliveryId }))
        .filter(option => option.counted)
        .slice(0, 3);

    if (!found.length) return "";

    return `If these items were bought with one of its expenses, link them to it ("Bought with expense") so the money is not counted twice: ${found
        .map(option => `${option.expenseCode} (${money(option.remaining, String(option.currency || funding.BASE_CURRENCY).toUpperCase())} not yet linked${option.description ? `, ${option.description}` : ""})`)
        .join("; ")}.`;

};


// ---------- possible double counting ----------

const review = async (organizationId) => {

    const expenses =
        await Expense.find({
            organization: organizationId,
            isDeleted: { $ne: true },
            donation: { $ne: null },
            status: { $in: funding.COUNTED_EXPENSE_STATUS }
        })
            .select("expenseCode description amount currency budgetAmount budgetCurrency expenseDate status project donation")
            .lean();

    if (!expenses.length) return [];

    const donations =
        await Donation.find({ _id: { $in: [...new Set(expenses.map(expense => toId(expense.donation)))] }, organization: organizationId })
            .select("donationCode title currency")
            .lean();
    const donationById = new Map(donations.map(donation => [toId(donation._id), donation]));

    const cost = await linkedCost(expenses, organizationId);

    const deliveries =
        await ServiceDelivery.find({
            organization: organizationId,
            isDeleted: false,
            status: { $ne: "Cancelled" },
            "items.donation": { $in: donations.map(donation => donation._id) }
        })
            .select("deliveryNumber deliveryDate project items")
            .populate("items.serviceType", "value name")
            .lean();

    const pairs = [];

    for (const delivery of deliveries) {
        (delivery.items || []).forEach((item, index) => {

            if (item.paidByExpense || !item.donation) return;

            const donation = donationById.get(toId(item.donation));
            if (!donation) return;

            const currency = String(donation.currency || funding.BASE_CURRENCY).toUpperCase();
            const value = funding.itemInCurrency(item, currency);
            if (!value) return;

            const separate = new Set((item.separateFromExpenses || []).map(toId));

            for (const expense of expenses) {

                if (toId(expense.donation) !== toId(item.donation)) continue;
                if (separate.has(toId(expense._id))) continue;
                if (delivery.project && expense.project && toId(delivery.project) !== toId(expense.project)) continue;

                const inDonation = funding.expenseInCurrency(expense, currency);
                if (inDonation === null || !Number(expense.amount)) continue;

                const remaining = Number(expense.amount) - (cost.get(toId(expense._id)) || 0);
                const remainingInDonation = inDonation * (remaining / Number(expense.amount));
                if (remainingInDonation <= 0.009) continue;
                if (Math.abs(remainingInDonation - value) > value * CLOSE) continue;

                pairs.push({
                    donation: { _id: donation._id, donationCode: donation.donationCode, title: donation.title, currency },
                    delivery: { _id: delivery._id, deliveryNumber: delivery.deliveryNumber, deliveryDate: delivery.deliveryDate },
                    item: { _id: item._id, name: itemName(item, index), value: round(value) },
                    expense: {
                        _id: expense._id,
                        expenseCode: expense.expenseCode,
                        description: expense.description,
                        expenseDate: expense.expenseDate,
                        status: expense.status,
                        value: round(remainingInDonation)
                    }
                });

            }

        });
    }

    return pairs.sort((a, b) => String(a.donation.donationCode).localeCompare(String(b.donation.donationCode)));

};


// ---------- link, or mark as separate ----------

const setLink = async ({ organizationId, deliveryId, itemId, expense, separate = false, userId = null }) => {

    if (!mongoose.isValidObjectId(deliveryId) || !mongoose.isValidObjectId(itemId) || !mongoose.isValidObjectId(expense)) {
        throw new ApiError("Invalid delivery, item or expense.", 400);
    }

    const delivery = await ServiceDelivery.findOne({ _id: deliveryId, organization: organizationId, isDeleted: false });
    if (!delivery) throw new ApiError("Service delivery not found.", 404);

    const item = delivery.items.id(itemId);
    if (!item) throw new ApiError("Service item not found.", 404);

    if (separate) {
        if (!item.separateFromExpenses.some(id => toId(id) === toId(expense))) item.separateFromExpenses.push(expense);
    }
    else {
        const plain = delivery.items.map(entry => (toId(entry._id) === toId(itemId) ? { ...entry.toObject(), paidByExpense: expense } : entry.toObject()));
        await checkLinks(plain, organizationId, { project: delivery.project, excludeDeliveryId: delivery._id });
        const checked = plain.find(entry => toId(entry._id) === toId(itemId));
        item.paidByExpense = expense;
        item.donation = checked.donation || item.donation;
        item.donor = checked.donor || item.donor;
        item.separateFromExpenses = checked.separateFromExpenses || [];
    }

    if (userId && delivery.schema.path("updatedBy")) delivery.updatedBy = userId;

    await delivery.save();

    return { _id: delivery._id, deliveryNumber: delivery.deliveryNumber, item: { _id: item._id, paidByExpense: item.paidByExpense, separateFromExpenses: item.separateFromExpenses } };

};


module.exports = {
    checkLinks,
    options,
    refusalHint,
    review,
    setLink
};
