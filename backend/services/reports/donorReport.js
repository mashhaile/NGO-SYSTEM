const mongoose = require("mongoose");

const Donor = require("../../models/donor");
const Donation = require("../../models/donation");
const ServiceDelivery = require("../../models/ServiceDelivery");
const ServiceDeliveryBeneficiary = require("../../models/ServiceDeliveryBeneficiary");

const {
    COUNTED_DELIVERY_FILTER
} = require("../../constants/serviceDeliveryStatus");

const {
    buildDateFilter
} = require("./reportFilters");

const {
    formatTotals
} = require("../budgetFigures");


// =====================================================
// DONOR REPORT
// =====================================================
// Per donor: received and pledged amounts (per currency,
// never added across currencies), programs and projects
// supported, services delivered with the donor's money and
// beneficiaries reached. A delivery counts when it or one of
// its items names the donor or one of its donations.

const generate = async (
    filters = {},
    context
) => {

    const { organizationId } = context;

    const donorQuery = { organization: organizationId, isDeleted: false };

    if (mongoose.isValidObjectId(filters.donor)) {
        donorQuery._id = filters.donor;
    }

    const donors = await Donor.find(donorQuery).sort({ name: 1 }).lean();

    const rows = [];
    const receivedAll = {};
    const pledgedAll = {};

    for (const donor of donors) {

        const donations =
            await Donation.find({
                organization: organizationId,
                donor: donor._id,
                isDeleted: false,
                status: { $ne: "Cancelled" },
                ...buildDateFilter(filters, "donationDate")
            })
                .populate("program", "name")
                .populate("project", "name")
                .lean();

        const donationIds = donations.map(donation => donation._id);

        const received = {};
        const pledged = {};
        for (const donation of donations) {
            const currency = donation.currency || "ETB";
            const target = donation.status === "Pledged" ? pledged : received;
            const all = donation.status === "Pledged" ? pledgedAll : receivedAll;
            target[currency] = (target[currency] || 0) + Number(donation.amount || 0);
            all[currency] = (all[currency] || 0) + Number(donation.amount || 0);
        }

        const deliveries =
            await ServiceDelivery.find({
                organization: organizationId,
                isDeleted: false,
                ...COUNTED_DELIVERY_FILTER,
                $or: [
                    { donation: { $in: donationIds } },
                    { "items.donation": { $in: donationIds } },
                    { "items.donor": donor._id }
                ]
            })
                .select("_id beneficiary")
                .lean();

        const linked =
            deliveries.length
                ? await ServiceDeliveryBeneficiary.distinct("beneficiary", {
                    organization: organizationId,
                    serviceDelivery: { $in: deliveries.map(delivery => delivery._id) }
                })
                : [];

        const beneficiaries = new Set([
            ...linked.map(String),
            ...deliveries.filter(delivery => delivery.beneficiary).map(delivery => String(delivery.beneficiary))
        ]);

        const supported = [
            ...new Set(
                donations
                    .map(donation => donation.project?.name || donation.program?.name)
                    .filter(Boolean)
            )
        ];

        rows.push({
            donor: donor.name,
            donorType: donor.donorType,
            country: donor.country || "-",
            donations: donations.length,
            received: formatTotals(received),
            pledged: formatTotals(pledged),
            supporting: supported.join(", ") || "General",
            servicesDelivered: deliveries.length,
            beneficiariesReached: beneficiaries.size,
            receivedETB: received.ETB || 0
        });

    }

    return {

        title: "Donor Report",

        summary: {
            totalDonors: rows.length,
            totalReceived: formatTotals(receivedAll),
            totalPledged: formatTotals(pledgedAll),
            totalServices: rows.reduce((sum, row) => sum + row.servicesDelivered, 0)
        },

        statistics: {},

        charts: {
            receivedByDonor: rows.map(row => ({ donor: `${row.donor} (ETB)`, amount: row.receivedETB })),
            beneficiariesByDonor: rows.map(row => ({ donor: row.donor, beneficiaries: row.beneficiariesReached }))
        },

        details: rows.map(({ receivedETB, ...row }) => row)

    };

};


module.exports = {
    generate
};
