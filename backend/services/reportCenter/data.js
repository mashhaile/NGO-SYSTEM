// =====================================================
// REPORT CENTER: SHARED DATA
// =====================================================
//
// What every report counts the same way:
//
//   deliveries  delivered (not cancelled) service deliveries
//   links       who was on each delivery, with the value
//               THEY received: their own allocation, or an
//               equal share of what the others' allocations
//               leave (households, groups and institutions
//               are not split among people)
//
// =====================================================

const ServiceDelivery = require("../../models/ServiceDelivery");
const ServiceDeliveryBeneficiary = require("../../models/ServiceDeliveryBeneficiary");

const {
    getBeneficiarySupportValue,
    buildDeliveryShares,
    memberItems
} = require("../reports/beneficiaryShares");

const { scope, toId, round2, toNumber } = require("./core");
const { inPeriod } = require("./period");


// Delivered deliveries in the period, optionally narrowed
// (program, project, activity, location …)
const loadDeliveries = async (organizationId, period, extra = {}) => {

    const dateCondition = inPeriod(period);

    return ServiceDelivery.find(
        scope(organizationId, {
            status: { $ne: "Cancelled" },
            ...(dateCondition ? { deliveryDate: dateCondition } : {}),
            ...extra
        })
    )
        .populate("program", "programCode name")
        .populate("project", "projectCode name")
        .populate("activity", "activityCode name")
        .populate("activityRun", "runCode name")
        .populate("items.serviceType", "value code")
        .populate("items.serviceCategory", "value code")
        .populate("items.unit", "value code semanticType")
        .populate("items.donation", "donationCode title currency")
        .populate("items.donor", "name")
        .sort({ deliveryDate: 1 })
        .lean();

};


// The people on those deliveries, each with their own value
const loadServedLinks = async (organizationId, deliveries, extra = {}) => {

    if (!deliveries.length) return [];

    const byId = new Map(deliveries.map(delivery => [toId(delivery._id), delivery]));

    const links =
        await ServiceDeliveryBeneficiary.find({
            organization: organizationId,
            serviceDelivery: { $in: deliveries.map(delivery => delivery._id) },
            ...extra
        })
            .select("serviceDelivery beneficiary allocations status")
            .lean();

    const withDelivery =
        links
            .filter(link => byId.has(toId(link.serviceDelivery)))
            .map(link => ({ ...link, serviceDelivery: byId.get(toId(link.serviceDelivery)) }));

    const shares = await buildDeliveryShares(organizationId, withDelivery);

    return withDelivery.map(link => {
        const value = getBeneficiarySupportValue(link, shares);
        return {
            ...link,
            beneficiaryId: toId(link.beneficiary),
            value,
            // what this person received of each item
            items: memberItems(link.serviceDelivery, link, value)
        };
    });

};


// A person's value split over the items of a delivery:
// their own allocations on an item, or (equal share) in
// proportion to each item's cost. Adds up to link.value.
const itemValues = (link) => {

    const items = link.serviceDelivery?.items || [];
    const allocations = Array.isArray(link.allocations) ? link.allocations : [];

    if (allocations.length) {
        return items.map(item => ({
            item,
            value: round2(allocations
                .filter(allocation => toId(allocation.serviceItem) === toId(item._id))
                .reduce((sum, allocation) => sum + toNumber(allocation.allocatedValue), 0))
        }));
    }

    const cost = items.reduce((sum, item) => sum + toNumber(item.totalCost), 0);

    return items.map(item => ({
        item,
        value: cost > 0 ? round2(link.value * (toNumber(item.totalCost) / cost)) : 0
    }));

};


// Money items (cash, fees) count by their amount
const isMoneyUnit = (unit) =>
    String(unit?.semanticType || "").toLowerCase() === "monetary" ||
    ["ETB", "BIRR", "USD", "EUR"].includes(String(unit?.code || unit?.value || "").toUpperCase());

const unitName = (unit) => unit?.value || unit?.code || "";

const serviceName = (item) => item?.serviceType?.value || "Service";

// "12.5 Kg", "3 Session"; money shows its amount. Given a
// person's own quantity (from memberItems), a money item's
// quantity already is their amount.
const quantityText = (item, ownQuantity) => {
    const amount =
        ownQuantity !== undefined
            ? ownQuantity
            : isMoneyUnit(item?.unit) ? item?.totalCost : item?.quantity;
    return `${round2(toNumber(amount)).toLocaleString("en-US")} ${unitName(item?.unit)}`.trim();
};

// value each delivery gives to individual people vs to
// households / groups / institutions as a whole
const splitDeliveryValue = (delivery) =>
    (delivery.recipientType || "Individual") === "Individual"
        ? { toPeople: toNumber(delivery.totalAmount), toGroups: 0 }
        : { toPeople: 0, toGroups: toNumber(delivery.totalAmount) };


module.exports = {
    loadDeliveries,
    loadServedLinks,
    itemValues,
    isMoneyUnit,
    unitName,
    serviceName,
    quantityText,
    splitDeliveryValue
};
