const ServiceDelivery = require("../../models/ServiceDelivery");
const ServiceDeliveryBeneficiary = require("../../models/ServiceDeliveryBeneficiary");

const {
    COUNTED_DELIVERY_FILTER
} = require("../../constants/serviceDeliveryStatus");

const {
    buildDateFilter
} = require("./reportFilters");


// =====================================================
// MONTHLY SERVICE REPORT
// =====================================================
// Deliveries per month (by delivery date): number of
// deliveries, beneficiaries reached (from the delivery's
// beneficiary records, each person counted once per month)
// and total value. Cancelled deliveries are not counted.

const round = (value) => Math.round(Number(value || 0) * 100) / 100;

const generate = async (
    filters = {},
    context
) => {

    const { organizationId } = context;

    const deliveries =
        await ServiceDelivery.find({
            organization: organizationId,
            isDeleted: false,
            ...COUNTED_DELIVERY_FILTER,
            deliveryDate: { $exists: true, $ne: null },
            ...buildDateFilter(filters, "deliveryDate")
        })
            .select("deliveryDate totalAmount beneficiary")
            .sort({ deliveryDate: 1 })
            .lean();

    const records =
        deliveries.length
            ? await ServiceDeliveryBeneficiary.find({
                organization: organizationId,
                serviceDelivery: { $in: deliveries.map(delivery => delivery._id) }
            })
                .select("serviceDelivery beneficiary")
                .lean()
            : [];

    const peopleByDelivery = {};
    for (const record of records) {
        const key = String(record.serviceDelivery);
        (peopleByDelivery[key] = peopleByDelivery[key] || []).push(String(record.beneficiary));
    }

    const months = new Map();

    for (const delivery of deliveries) {
        const date = new Date(delivery.deliveryDate);
        const key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
        if (!months.has(key)) {
            months.set(key, { year: date.getFullYear(), month: date.getMonth() + 1, services: 0, people: new Set(), totalValue: 0 });
        }
        const month = months.get(key);
        month.services += 1;
        month.totalValue += Number(delivery.totalAmount || 0);
        for (const person of peopleByDelivery[String(delivery._id)] || []) month.people.add(person);
        if (delivery.beneficiary) month.people.add(String(delivery.beneficiary));
    }

    const details =
        [...months.values()].map(month => ({
            month: `${month.month}/${month.year}`,
            services: month.services,
            beneficiaries: month.people.size,
            totalValue: round(month.totalValue)
        }));

    const allPeople = new Set([...months.values()].flatMap(month => [...month.people]));

    return {

        title: "Monthly Service Report",

        summary: {
            totalMonths: details.length,
            totalServices: details.reduce((sum, item) => sum + item.services, 0),
            beneficiariesReached: allPeople.size,
            totalValue: round(details.reduce((sum, item) => sum + item.totalValue, 0))
        },

        statistics: {},

        charts: {
            servicesByMonth: details.map(item => ({ month: item.month, services: item.services })),
            valueByMonth: details.map(item => ({ month: item.month, amount: item.totalValue }))
        },

        details

    };

};


module.exports = {
    generate
};
