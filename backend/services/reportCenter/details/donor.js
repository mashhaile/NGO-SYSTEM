// =====================================================
// DONOR (detail report)
// =====================================================
//
// One donor: their donations, what each one paid for,
// and the people reached (numbers only; names are not in
// this report). Each donation opens its own "Where did it
// go?" trace.
//
// =====================================================

const Donor = require("../../../models/donor");
const Donation = require("../../../models/donation");
const Beneficiary = require("../../../models/Beneficiary");


const {
    scope, formatTotals, objectId, toId, round2, toNumber, lookupText, groupRows,
    summaryItem, column, section, buildReport, notFound
} = require("../core");

const { loadDeliveries, loadServedLinks, serviceName, quantityText } = require("../data");
const { donationUse } = require("../reports/donors");


const addTo = (totals, currency, amount) => {
    const key = currency || "ETB";
    totals[key] = round2((totals[key] || 0) + toNumber(amount));
    return totals;
};


const generate = async (id, query, context, period) => {

    const { organizationId } = context;

    const donor =
        objectId(id) &&
        await Donor.findOne(scope(organizationId, { _id: objectId(id) })).lean();

    if (!donor) throw notFound("Donor");

    const donations =
        await Donation.find(scope(organizationId, { donor: donor._id }))
            .populate("program", "name")
            .populate("project", "name")
            .sort({ donationDate: -1 })
            .lean();

    const donationIds = donations.map(donation => donation._id);

    const deliveries =
        donationIds.length
            ? await loadDeliveries(organizationId, period, { $or: [{ "items.donation": { $in: donationIds } }, { donation: { $in: donationIds } }] })
            : [];

    const links = await loadServedLinks(organizationId, deliveries);
    const use = donationUse(deliveries, links);

    const reached = new Set();
    const institutions = new Set();
    const groups = new Set();
    for (const entry of use.values()) {
        for (const person of entry.people) reached.add(person);
        for (const name of entry.institutions) institutions.add(name);
        for (const name of entry.groups) groups.add(name);
    }

    const people =
        reached.size
            ? await Beneficiary.find(scope(organizationId, { _id: { $in: [...reached].map(objectId) } }))
                .select("gender region zone woreda").populate("gender", "value").lean()
            : [];

    const ids = new Set(donationIds.map(toId));
    const received = donations.filter(donation => donation.status === "Received").reduce((totals, donation) => addTo(totals, donation.currency, donation.amount), {});
    const pledged = donations.filter(donation => donation.status === "Pledged").reduce((totals, donation) => addTo(totals, donation.currency, donation.amount), {});
    const used = donations.reduce((totals, donation) => {
        const amount = use.get(toId(donation._id))?.used || 0;
        return amount ? addTo(totals, donation.currency, amount) : totals;
    }, {});

    return buildReport({
        key: "donor",
        title: donor.name,
        description: "Donations, what each paid for and the people reached. Each donation opens its full trace.",
        period,
        record: {
            fields: [
                { label: "Type", value: donor.donorType },
                { label: "Country", value: donor.country },
                { label: "Contact person", value: donor.contactPerson },
                { label: "Email", value: donor.email },
                { label: "Phone", value: donor.phone },
                { label: "Donor since", value: donor.donorSince, format: "date" },
                { label: "Status", value: donor.status },
                { label: "Sees beneficiary names", value: donor.shareBeneficiaryNames ? "Yes" : "No" }
            ]
        },
        summary: [
            summaryItem("Donations", donations.length),
            summaryItem("Received", formatTotals(received), "text"),
            summaryItem("Pledged", formatTotals(pledged), "text"),
            summaryItem("Used on services", formatTotals(used), "text"),
            summaryItem("Beneficiaries reached", reached.size),
            summaryItem("Institutions reached", institutions.size),
            summaryItem("Households and groups reached", groups.size)
        ],
        sections: [
            section("donations", "Donations", [
                column("date", "Date", "date"),
                column("code", "Donation"),
                column("title", "Title"),
                column("program", "Program / project"),
                column("status", "Status"),
                column("amount", "Amount", "money"),
                column("currency", "Currency"),
                column("used", "Used", "money"),
                column("people", "Beneficiaries reached", "number"),
                column("institutions", "Institutions", "number"),
                column("groups", "Households / groups", "number")
            ], donations.map(donation => ({
                id: toId(donation._id),
                date: donation.donationDate,
                code: donation.donationCode,
                title: donation.title,
                program: [donation.program?.name, donation.project?.name].filter(Boolean).join(" / "),
                status: donation.status,
                amount: round2(donation.amount),
                currency: donation.currency || "ETB",
                used: round2(use.get(toId(donation._id))?.used || 0),
                people: use.get(toId(donation._id))?.people.size || 0,
                institutions: use.get(toId(donation._id))?.institutions.size || 0,
                groups: use.get(toId(donation._id))?.groups.size || 0
            })), { link: { kind: "donation", idKey: "id" } }),
            section("paidFor", "What the donations paid for", [
                column("date", "Date", "date"),
                column("delivery", "Delivery"),
                column("services", "Services"),
                column("recipient", "Recipient"),
                column("people", "Beneficiaries", "number"),
                column("value", "Cost", "money", { currency: "ETB" })
            ], deliveries.map(delivery => {
                const funded = (delivery.items || []).filter(item => ids.has(toId(item.donation)) || (!item.donation && ids.has(toId(delivery.donation))));
                return {
                    id: toId(delivery._id),
                    date: delivery.deliveryDate,
                    delivery: delivery.deliveryNumber,
                    services: funded.map(item => `${serviceName(item)} (${quantityText(item)})`).join("; "),
                    recipient: (delivery.recipientType || "Individual") === "Individual" ? "Individuals" : `${delivery.recipientType}${delivery.recipientName ? `: ${delivery.recipientName}` : ""}`,
                    people: links.filter(link => toId(link.serviceDelivery._id) === toId(delivery._id)).length,
                    value: round2(funded.reduce((sum, item) => sum + toNumber(item.totalCost), 0))
                };
            }), { link: { kind: "delivery", idKey: "id" } }),
            section("gender", "People reached, by gender", [column("label", "Gender"), column("people", "People", "number")],
                groupRows(people, person => lookupText(person.gender), { people: () => 1 }),
                { chart: { type: "pie", x: "label", series: ["people"] } }),
            section("region", "People reached, by region", [column("label", "Region"), column("people", "People", "number")],
                groupRows(people, person => person.region, { people: () => 1 }))
        ]
    });

};


module.exports = {
    kind: "donor",
    title: "Donor",
    generate
};
