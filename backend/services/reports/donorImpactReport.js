const mongoose = require("mongoose");

const Donor = require("../../models/donor");
const Donation = require("../../models/donation");
const Project = require("../../models/Project");
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
// DONOR IMPACT REPORT
// =====================================================
// Per donor: what was given (per currency), which programs
// it reached, and the services / beneficiaries it paid for.
//
// A service delivery counts for a donor when the delivery
// or one of its items names the donor or one of the donor's
// donations; its value is the total of those items only.

const round = (value) => Math.round(Number(value || 0) * 100) / 100;

const sameId = (a, b) => a && b && String(a._id || a) === String(b._id || b);


const generate = async (
    filters = {},
    context
) => {

    if (!context || !context.organizationId) {
        throw new Error("Report organization context is required.");
    }

    const organizationId = context.organizationId;

    const donorQuery = { organization: organizationId, isDeleted: false };

    if (mongoose.isValidObjectId(filters.donor)) {
        donorQuery._id = filters.donor;
    }

    const donors = await Donor.find(donorQuery).sort({ name: 1 }).lean();

    const rows = [];

    // Organization totals per currency
    const allGiven = {};

    for (const donor of donors) {

        const donations =
            await Donation.find({
                organization: organizationId,
                donor: donor._id,
                isDeleted: false,
                status: { $ne: "Cancelled" },
                ...buildDateFilter(filters, "donationDate")
            }).lean();

        const donationIds = donations.map(donation => donation._id);

        const deliveries =
            await ServiceDelivery.find({
                organization: organizationId,
                isDeleted: false,
                ...COUNTED_DELIVERY_FILTER,
                ...buildDateFilter(filters, "deliveryDate"),
                $or: [
                    { donation: { $in: donationIds } },
                    { "items.donation": { $in: donationIds } },
                    { "items.donor": donor._id }
                ]
            })
                .select("program donation beneficiary items")
                .lean();

        // Value of the items this donor paid for
        const isDonors = (item, delivery) =>
            sameId(item.donor, donor._id) ||
            donationIds.some(id => sameId(item.donation, id)) ||
            (!item.donor && !item.donation && donationIds.some(id => sameId(delivery.donation, id)));

        const serviceValue =
            deliveries.reduce(
                (sum, delivery) =>
                    sum + (delivery.items || [])
                        .filter(item => isDonors(item, delivery))
                        .reduce((total, item) => total + Number(item.totalCost || 0), 0),
                0
            );

        // Beneficiaries reached (association records + legacy single beneficiary)
        const deliveryIds = deliveries.map(delivery => delivery._id);
        const linked =
            deliveryIds.length
                ? await ServiceDeliveryBeneficiary.distinct("beneficiary", {
                    organization: organizationId,
                    serviceDelivery: { $in: deliveryIds }
                })
                : [];
        const beneficiaries = new Set([
            ...linked.map(String),
            ...deliveries.filter(delivery => delivery.beneficiary).map(delivery => String(delivery.beneficiary))
        ]);

        // Programs: from the donations (directly or via their project) and the deliveries
        const projectIds = donations.filter(donation => !donation.program && donation.project).map(donation => donation.project);
        const projectPrograms =
            projectIds.length
                ? (await Project.find({ _id: { $in: projectIds } }).select("program").lean()).map(project => project.program)
                : [];
        const programs = new Set(
            [
                ...donations.map(donation => donation.program),
                ...projectPrograms,
                ...deliveries.map(delivery => delivery.program)
            ]
                .filter(Boolean)
                .map(String)
        );

        // Given, per currency
        const given = {};
        // Given = received (a pledge is not money yet)
        for (const donation of donations.filter(item => item.status === "Received")) {
            const currency = donation.currency || "ETB";
            given[currency] = round((given[currency] || 0) + Number(donation.amount || 0));
            allGiven[currency] = round((allGiven[currency] || 0) + Number(donation.amount || 0));
        }

        rows.push({
            donor: donor.name,
            donorType: donor.donorType,
            donations: donations.length,
            totalDonated: formatTotals(given),
            donatedETB: given.ETB || 0,
            programsSupported: programs.size,
            servicesDelivered: deliveries.length,
            beneficiariesReached: beneficiaries.size,
            totalServiceValue: round(serviceValue),
            averageSupportPerBeneficiary:
                beneficiaries.size ? round(serviceValue / beneficiaries.size) : 0
        });

    }

    return {

        title: "Donor Impact Report",

        summary: {
            totalDonors: rows.length,
            totalFunding: formatTotals(allGiven),
            totalServicesDelivered: rows.reduce((sum, row) => sum + row.servicesDelivered, 0),
            totalServiceValue: round(rows.reduce((sum, row) => sum + row.totalServiceValue, 0))
        },

        statistics: {},

        charts: {
            fundingByDonor: rows.map(row => ({ donor: row.donor, amount: row.donatedETB })),
            beneficiariesByDonor: rows.map(row => ({ donor: row.donor, beneficiaries: row.beneficiariesReached })),
            serviceValueByDonor: rows.map(row => ({ donor: row.donor, value: row.totalServiceValue }))
        },

        details: rows.map(({ donatedETB, ...row }) => row)

    };

};


module.exports = {
    generate
};
