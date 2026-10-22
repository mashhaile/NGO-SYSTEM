// =====================================================
// ENTERPRISE PROFILE (detail report)
// =====================================================
//
// One enterprise: its members and the support each one
// received (their own share), and what it was.
//
// =====================================================

const {
    objectId, toId, round2, lookupText, locationText, fullName, groupRows,
    summaryItem, column, section, buildReport, notFound
} = require("../core");

const { serviceName, quantityText, itemValues } = require("../data");
const { loadEnterpriseSupport } = require("../reports/enterprises");


const generate = async (id, query, context, period) => {

    const { organizationId } = context;

    if (!objectId(id)) throw notFound("Enterprise");

    const { enterprises, members, links } = await loadEnterpriseSupport(organizationId, period, { _id: objectId(id) });

    const enterprise = enterprises[0];

    if (!enterprise) throw notFound("Enterprise");

    const valueOf = (beneficiaryId) =>
        round2(links.filter(link => link.beneficiaryId === beneficiaryId).reduce((sum, link) => sum + link.value, 0));

    const supportRows =
        links
            .sort((a, b) => new Date(b.serviceDelivery.deliveryDate) - new Date(a.serviceDelivery.deliveryDate))
            .map(link => {
                const member = members.find(item => toId(item.beneficiary?._id) === link.beneficiaryId);
                return {
                    id: toId(link.serviceDelivery._id),
                    date: link.serviceDelivery.deliveryDate,
                    delivery: link.serviceDelivery.deliveryNumber,
                    member: member ? fullName(member.beneficiary) : "",
                    services: link.items.filter(item => item.quantity > 0).map(item => `${serviceName(item)} (${quantityText(item, item.quantity)})`).join("; ") || "—",
                    value: link.value
                };
            });

    const total = round2(links.reduce((sum, link) => sum + link.value, 0));

    return buildReport({
        key: "enterprise",
        title: enterprise.name,
        description: `Enterprise ${enterprise.enterpriseNumber}: members and the support they received.`,
        period,
        record: {
            fields: [
                { label: "Enterprise No.", value: enterprise.enterpriseNumber },
                { label: "Type", value: lookupText(enterprise.enterpriseType) },
                { label: "Ownership", value: lookupText(enterprise.ownershipType) },
                { label: "Business sector", value: lookupText(enterprise.businessSector) },
                { label: "Started", value: enterprise.startDate, format: "date" },
                { label: "Location", value: [enterprise.kebele, locationText(enterprise)].filter(Boolean).join(", ") },
                { label: "Phone", value: enterprise.phone },
                { label: "Status", value: enterprise.status }
            ]
        },
        summary: [
            summaryItem("Members", members.length),
            summaryItem("Women members", members.filter(member => /^female$/i.test(lookupText(member.beneficiary?.gender))).length),
            summaryItem("Members supported", new Set(links.map(link => link.beneficiaryId)).size),
            summaryItem("Deliveries", new Set(links.map(link => toId(link.serviceDelivery._id))).size),
            summaryItem("Support to members", total, "money", { currency: "ETB" })
        ],
        sections: [
            section("members", "Members", [
                column("number", "No."),
                column("name", "Member"),
                column("gender", "Gender"),
                column("role", "Role"),
                column("joined", "Joined", "date"),
                column("status", "Status"),
                column("value", "Support received", "money", { currency: "ETB" })
            ], members.map(member => ({
                id: toId(member.beneficiary?._id),
                number: member.beneficiary?.beneficiaryNumber || "",
                name: member.beneficiary ? fullName(member.beneficiary) : "",
                gender: lookupText(member.beneficiary?.gender),
                role: member.memberRole,
                joined: member.joinedDate,
                status: member.status,
                value: valueOf(toId(member.beneficiary?._id))
            })), { link: { kind: "beneficiary", idKey: "id" }, total: { value: total } }),
            section("byService", "Support by service", [
                column("label", "Service"),
                column("deliveries", "Times received", "number"),
                column("value", "Value", "money", { currency: "ETB" })
            ], groupRows(
                links.flatMap(link => itemValues(link).filter(entry => entry.value > 0)),
                entry => serviceName(entry.item),
                { deliveries: () => 1, value: entry => entry.value }
            )),
            section("support", "Support received", [
                column("date", "Date", "date"),
                column("delivery", "Delivery"),
                column("member", "Member"),
                column("services", "What they received"),
                column("value", "Value", "money", { currency: "ETB" })
            ], supportRows, { link: { kind: "delivery", idKey: "id" }, total: { value: total } })
        ]
    });

};


module.exports = {
    kind: "enterprise",
    title: "Enterprise profile",
    generate
};
