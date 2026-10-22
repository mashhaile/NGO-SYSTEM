const mongoose = require("mongoose");
const ServiceDeliveryBeneficiary = require("../../models/ServiceDeliveryBeneficiary");

// =====================================================
// A PERSON'S SHARE OF A DELIVERY
// =====================================================
// A person counts what THEY received, never the whole
// delivery: their own allocated value, or (no allocation of
// their own) an equal share of what the delivery's other
// allocations leave. Households, groups and institutions
// are not support to one person, so they count 0 here.
//
// shares: Map deliveryId -> { left, peopleWithoutShare }
// (from buildDeliveryShares, counting EVERYONE on the
// delivery, not only the people in this report)

const roundMoney = (value) =>
    Math.round(Number(value || 0) * 100) / 100;

const getBeneficiarySupportValue = (
    link,
    shares
) => {

    const service =
        link?.serviceDelivery;

    if (!service) {

        return 0;

    }

    if (
        (service.recipientType || "Individual") !== "Individual"
    ) {

        return 0;

    }

    const allocations =
        Array.isArray(link.allocations) ? link.allocations : [];

    if (allocations.length > 0) {

        return roundMoney(
            allocations.reduce((sum, allocation) => sum + Number(allocation?.allocatedValue || 0), 0)
        );

    }

    const share =
        shares?.get(String(service._id || service));

    if (!share || share.peopleWithoutShare === 0) {

        return 0;

    }

    return roundMoney(share.left / share.peopleWithoutShare);

};


// Per delivery: value not covered by personal allocations,
// and how many people on it have no allocation of their own
const buildDeliveryShares = async (
    organizationId,
    links
) => {

    const deliveries =
        new Map();

    for (const link of links) {
        const service = link?.serviceDelivery;
        if (service?._id) deliveries.set(String(service._id), Number(service.totalAmount || 0));
    }

    if (deliveries.size === 0) {
        return new Map();
    }

    const rows =
        await ServiceDeliveryBeneficiary.aggregate([
            {
                $match: {
                    organization: new mongoose.Types.ObjectId(String(organizationId)),
                    serviceDelivery: { $in: [...deliveries.keys()].map(id => new mongoose.Types.ObjectId(id)) }
                }
            },
            {
                $project: {
                    serviceDelivery: 1,
                    allocated: { $sum: { $ifNull: ["$allocations.allocatedValue", []] } },
                    hasShare: { $gt: [{ $size: { $ifNull: ["$allocations", []] } }, 0] }
                }
            },
            {
                $group: {
                    _id: "$serviceDelivery",
                    allocated: { $sum: "$allocated" },
                    peopleWithoutShare: { $sum: { $cond: ["$hasShare", 0, 1] } }
                }
            }
        ]);

    return new Map(
        rows.map(row => [
            String(row._id),
            {
                left: Math.max(0, (deliveries.get(String(row._id)) || 0) - Number(row.allocated || 0)),
                peopleWithoutShare: row.peopleWithoutShare
            }
        ])
    );

};

// =====================================================
// DELIVERIES OF A GROUP OF PEOPLE (enterprise members)
// =====================================================
// People are linked to a delivery through
// ServiceDeliveryBeneficiary; old deliveries kept one person
// on the delivery itself. Both count.

const findMemberDeliveryScope = async (
    organizationId,
    beneficiaryIds
) => {

    const links =
        await ServiceDeliveryBeneficiary.find({
            organization: organizationId,
            beneficiary: { $in: beneficiaryIds }
        })
        .select("serviceDelivery beneficiary allocations")
        .lean();

    return {

        links,

        filter: {
            $or: [
                { beneficiary: { $in: beneficiaryIds } },
                { _id: { $in: links.map(link => link.serviceDelivery) } }
            ]
        }

    };

};


// What one person received of each item: their own
// allocated quantity; with detail-only allocations, in
// proportion to their value on the item; with no allocation
// of their own, their share of the delivery. Everyone on a
// participation item (a training) took part in all of it.
const memberItems = (delivery, link, personValue) => {

    const allocations =
        Array.isArray(link.allocations) ? link.allocations : [];

    const deliveryTotal =
        Number(delivery.totalAmount || 0);

    const individual =
        (delivery.recipientType || "Individual") === "Individual";

    const round3 = (value) =>
        Math.round(Number(value || 0) * 1000) / 1000;

    return (delivery.items || []).map(item => {

        const quantity =
            Number(item.quantity || 0);

        const behavior =
            String(item.allocationBehavior || item.serviceType?.allocationBehavior || "").toUpperCase();

        let own;

        if (!individual) {
            own = 0;
        }
        else if (behavior === "PARTICIPATION") {
            own = quantity;
        }
        else if (allocations.length === 0) {
            own = deliveryTotal > 0 ? quantity * (personValue / deliveryTotal) : 0;
        }
        else {
            const onItem =
                allocations.filter(allocation => String(allocation?.serviceItem) === String(item._id));
            const direct =
                onItem.filter(allocation => !allocation?.detailItem);
            const itemCost =
                Number(item.totalCost || 0) || quantity * Number(item.unitCost || 0);
            const directQuantity =
                direct.reduce((sum, allocation) => sum + Number(allocation?.quantity || 0), 0);
            const directValue =
                direct.reduce((sum, allocation) => sum + Number(allocation?.allocatedValue || 0), 0);
            // a cash share is an amount with no quantity: the
            // amount is what they received (4,000 ETB of a
            // 40,000 ETB cash item counts as 4,000 ETB, as in
            // the donor trace)
            own = direct.length && directQuantity > 0
                ? directQuantity
                : direct.length && directValue > 0
                    ? directValue
                    : itemCost > 0
                    ? quantity * (onItem.reduce((sum, allocation) => sum + Number(allocation?.allocatedValue || 0), 0) / itemCost)
                    : 0;
        }

        return {
            ...item,
            deliveredQuantity: quantity,
            quantity: round3(own)
        };

    });

};


// One row per person and delivery: the delivery as that
// person received it (beneficiary = the person, totalAmount =
// their own share, items = their own quantities), so a
// delivery to three members is not counted three times.
const expandToMembers = async (
    organizationId,
    deliveries,
    links,
    beneficiaryIds
) => {

    const Beneficiary = require("../../models/Beneficiary");

    const wanted =
        new Set(beneficiaryIds.map(id => String(id?._id || id)));

    const people =
        new Map(
            (await Beneficiary.find({ _id: { $in: [...wanted] } })
                .select("beneficiaryNumber firstName middleName lastName")
                .lean())
                .map(person => [String(person._id), person])
        );

    const plain =
        deliveries.map(delivery => (typeof delivery.toObject === "function" ? delivery.toObject() : delivery));

    const byId =
        new Map(plain.map(delivery => [String(delivery._id), delivery]));

    const ownLinks =
        links
            .filter(link => byId.has(String(link.serviceDelivery)) && wanted.has(String(link.beneficiary)))
            .map(link => ({ ...link, serviceDelivery: byId.get(String(link.serviceDelivery)) }));

    const shares =
        await buildDeliveryShares(organizationId, ownLinks);

    const linksByDelivery = new Map();

    for (const link of ownLinks) {
        const id = String(link.serviceDelivery._id);
        if (!linksByDelivery.has(id)) linksByDelivery.set(id, []);
        linksByDelivery.get(id).push(link);
    }

    // Same order as the query
    const rows = [];

    for (const delivery of plain) {

        const deliveryLinks =
            linksByDelivery.get(String(delivery._id));

        if (deliveryLinks) {

            for (const link of deliveryLinks) {
                const personValue =
                    getBeneficiarySupportValue(link, shares);
                rows.push({
                    ...delivery,
                    beneficiary: people.get(String(link.beneficiary)) || { _id: link.beneficiary },
                    items: memberItems(delivery, link, personValue),
                    deliveryTotalAmount: Number(delivery.totalAmount || 0),
                    totalAmount: personValue
                });
            }

            continue;

        }

        // Old deliveries: one person on the delivery itself
        const personId =
            String(delivery.beneficiary?._id || delivery.beneficiary || "");

        if (wanted.has(personId)) {
            rows.push({
                ...delivery,
                beneficiary: people.get(personId) || delivery.beneficiary,
                deliveryTotalAmount: Number(delivery.totalAmount || 0)
            });
        }

    }

    return rows;

};


module.exports = {
    roundMoney,
    getBeneficiarySupportValue,
    buildDeliveryShares,
    findMemberDeliveryScope,
    expandToMembers,
    memberItems
};
