// =====================================================
// DONORS & FUNDING REPORT
// =====================================================
//
// Who funds the organization, the donations received and
// pledged, what each donation paid for and who it reached.
// Replaces the Donor, Donor Impact and Financial reports.
//
// Money is kept per currency and never added across
// currencies. "Used" is the cost of delivered items
// charged to a donation (as in its "Where did it go?"
// trace).
//
// Filters: program
//
// =====================================================

const Donor = require("../../../models/donor");
const Donation = require("../../../models/donation");


const {
    scope, formatTotals, objectId, toId, round2, toNumber, groupRows,
    summaryItem, column, section, buildReport
} = require("../core");

const { inPeriod, monthKey, monthName } = require("../period");
const { loadDeliveries, loadServedLinks, INSTITUTION, HOUSEHOLD_OR_GROUP } = require("../data");


const addTo = (totals, currency, amount) => {
    const key = currency || "ETB";
    totals[key] = round2((totals[key] || 0) + toNumber(amount));
    return totals;
};


// For each donation: what its items cost and who they reached
const donationUse = (deliveries, links) => {

    const use = new Map();

    for (const delivery of deliveries) {
        const funded = new Map();
        for (const item of delivery.items || []) {
            const donationId = toId(item.donation) || toId(delivery.donation);
            if (!donationId) continue;
            const entry = funded.get(donationId) || { itemIds: new Set(), cost: 0 };
            entry.itemIds.add(toId(item._id));
            entry.cost += toNumber(item.totalCost);
            funded.set(donationId, entry);
        }
        for (const [donationId, entry] of funded) {
            const row = use.get(donationId) || { used: 0, deliveries: new Set(), people: new Set(), institutions: new Set(), groups: new Set() };
            row.used += entry.cost;
            row.deliveries.add(toId(delivery._id));
            // a school, a community group … reached as a whole
            const recipient = String(delivery.recipientName || delivery.deliveryNumber).trim().toLowerCase();
            if (INSTITUTION.includes(delivery.recipientType)) row.institutions.add(recipient);
            if (HOUSEHOLD_OR_GROUP.includes(delivery.recipientType)) row.groups.add(recipient);
            for (const link of links) {
                if (toId(link.serviceDelivery._id) !== toId(delivery._id)) continue;
                const allocations = link.allocations || [];
                // reached: received a funded item, or the delivery has no item-level shares
                if (!allocations.length || allocations.some(allocation => entry.itemIds.has(toId(allocation.serviceItem)))) {
                    row.people.add(link.beneficiaryId);
                }
            }
            use.set(donationId, row);
        }
    }

    return use;

};


const generate = async (query, context, period) => {

    const { organizationId } = context;

    const programFilter = objectId(query.program) ? { program: objectId(query.program) } : {};

    const donors =
        await Donor.find(scope(organizationId))
            .select("name donorType country status")
            .sort({ name: 1 })
            .lean();

    // all donations (balances), and those dated in the period
    const allDonations =
        await Donation.find(scope(organizationId, { status: { $ne: "Cancelled" }, ...programFilter }))
            .populate("donor", "name donorType")
            .populate("program", "name")
            .populate("project", "name")
            .sort({ donationDate: 1 })
            .lean();

    const dateCondition = inPeriod(period);
    const inThePeriod = (donation) =>
        !dateCondition ||
        ((!dateCondition.$gte || new Date(donation.donationDate) >= dateCondition.$gte) &&
            (!dateCondition.$lt || new Date(donation.donationDate) < dateCondition.$lt));

    const donations = allDonations.filter(inThePeriod);

    // what donations paid for: in the period, and to date
    const periodDeliveries = await loadDeliveries(organizationId, period, programFilter);
    const periodLinks = await loadServedLinks(organizationId, periodDeliveries);
    const periodUse = donationUse(periodDeliveries, periodLinks);

    const allDeliveries = await loadDeliveries(organizationId, { start: null, end: null }, programFilter);
    const allUse = donationUse(allDeliveries, []);

    // ---------- per donation ----------
    const donationRows = donations.map(donation => {
        const id = toId(donation._id);
        const use = periodUse.get(id);
        const usedToDate = round2(allUse.get(id)?.used || 0);
        const received = donation.status === "Received" ? round2(donation.amount) : 0;
        return {
            id,
            donorId: toId(donation.donor?._id),
            code: donation.donationCode,
            title: donation.title,
            donor: donation.donor?.name || "",
            date: donation.donationDate,
            status: donation.status,
            restriction: donation.fundingRestriction || "",
            source: donation.fundingSource || "",
            program: donation.program?.name || "",
            project: donation.project?.name || "",
            currency: donation.currency || "ETB",
            amount: round2(donation.amount),
            usedInPeriod: round2(use?.used || 0),
            usedToDate,
            remaining: received ? round2(Math.max(received - usedToDate, 0)) : null,
            people: use?.people.size || 0,
            institutions: use?.institutions.size || 0,
            groups: use?.groups.size || 0
        };
    });

    // ---------- per donor ----------
    const donorRows = donors.map(donor => {
        const id = toId(donor._id);
        const own = donationRows.filter(row => row.donorId === id);
        const people = new Set();
        const institutions = new Set();
        const groups = new Set();
        for (const row of own) {
            for (const person of periodUse.get(row.id)?.people || []) people.add(person);
            for (const name of periodUse.get(row.id)?.institutions || []) institutions.add(name);
            for (const name of periodUse.get(row.id)?.groups || []) groups.add(name);
        }
        return {
            id,
            name: donor.name,
            type: donor.donorType || "",
            country: donor.country || "",
            donations: own.length,
            received: formatTotals(own.filter(row => row.status === "Received").reduce((totals, row) => addTo(totals, row.currency, row.amount), {})),
            pledged: formatTotals(own.filter(row => row.status === "Pledged").reduce((totals, row) => addTo(totals, row.currency, row.amount), {})),
            used: formatTotals(own.reduce((totals, row) => (row.usedInPeriod ? addTo(totals, row.currency, row.usedInPeriod) : totals), {})),
            people: people.size,
            institutions: institutions.size,
            groups: groups.size
        };
    }).filter(row => row.donations > 0 || !query.program);

    const received = donationRows.filter(row => row.status === "Received").reduce((totals, row) => addTo(totals, row.currency, row.amount), {});
    const pledged = donationRows.filter(row => row.status === "Pledged").reduce((totals, row) => addTo(totals, row.currency, row.amount), {});
    const usedTotals = donationRows.reduce((totals, row) => (row.usedInPeriod ? addTo(totals, row.currency, row.usedInPeriod) : totals), {});
    const reached = new Set();
    const institutionsReached = new Set();
    const groupsReached = new Set();
    for (const use of periodUse.values()) {
        for (const person of use.people) reached.add(person);
        for (const name of use.institutions) institutionsReached.add(name);
        for (const name of use.groups) groupsReached.add(name);
    }

    // received per month and currency
    const monthRows = (() => {
        const map = new Map();
        for (const row of donationRows.filter(item => item.status === "Received")) {
            const key = `${monthKey(row.date)}|${row.currency}`;
            const entry = map.get(key) || { key: monthKey(row.date), currency: row.currency, donations: 0, amount: 0 };
            entry.donations += 1;
            entry.amount += row.amount;
            map.set(key, entry);
        }
        return [...map.values()].sort((a, b) => a.key.localeCompare(b.key) || a.currency.localeCompare(b.currency))
            .map(entry => ({ label: monthName(entry.key), currency: entry.currency, donations: entry.donations, amount: round2(entry.amount) }));
    })();

    const byCurrency = (keyOf) => {
        const map = new Map();
        for (const row of donationRows) {
            const key = `${keyOf(row) || "Not specified"}|${row.currency}`;
            const entry = map.get(key) || { label: keyOf(row) || "Not specified", currency: row.currency, donations: 0, amount: 0 };
            entry.donations += 1;
            entry.amount += row.amount;
            map.set(key, entry);
        }
        return [...map.values()].map(entry => ({ ...entry, amount: round2(entry.amount) })).sort((a, b) => b.amount - a.amount);
    };

    const currencyColumns = (first) => [
        column("label", first),
        column("donations", "Donations", "number"),
        column("amount", "Amount", "money"),
        column("currency", "Currency")
    ];

    return buildReport({
        key: "donors",
        title: "Donors & funding",
        description: "Donors, donations received and pledged, what each donation paid for and who it reached. Amounts are never added across currencies.",
        period,
        summary: [
            summaryItem("Donors", donors.length, "number", { note: `${donors.filter(donor => donor.status !== "Inactive").length} active` }),
            summaryItem("Donations in the period", donationRows.length),
            summaryItem("Received", formatTotals(received), "text"),
            summaryItem("Pledged, not yet received", formatTotals(pledged), "text"),
            summaryItem("Used on services in the period", formatTotals(usedTotals), "text"),
            summaryItem("Beneficiaries reached through donations", reached.size),
            summaryItem("Institutions reached through donations", institutionsReached.size),
            summaryItem("Households and groups reached through donations", groupsReached.size)
        ],
        sections: [
            section("donors", "By donor", [
                column("name", "Donor"),
                column("type", "Type"),
                column("country", "Country"),
                column("donations", "Donations", "number"),
                column("received", "Received"),
                column("pledged", "Pledged"),
                column("used", "Used in period"),
                column("people", "Beneficiaries reached", "number"),
                column("institutions", "Institutions reached", "number"),
                column("groups", "Households / groups reached", "number")
            ], donorRows, { link: { kind: "donor", idKey: "id" } }),
            section("month", "Received by month", [
                column("label", "Month"),
                column("donations", "Donations", "number"),
                column("amount", "Received", "money"),
                column("currency", "Currency")
            ], monthRows),
            section("source", "By funding source", currencyColumns("Source"), byCurrency(row => row.source)),
            section("restriction", "Restricted or unrestricted", currencyColumns("Restriction"), byCurrency(row => row.restriction)),
            section("program", "By program", currencyColumns("Program"), byCurrency(row => row.program))
        ],
        details: {
            title: "Donations",
            link: { kind: "donation", idKey: "id" },
            columns: [
                column("code", "Donation"),
                column("title", "Title"),
                column("donor", "Donor"),
                column("date", "Date", "date"),
                column("status", "Status"),
                column("program", "Program"),
                column("amount", "Amount", "money"),
                column("currency", "Currency"),
                column("usedInPeriod", "Used in period", "money"),
                column("usedToDate", "Used to date", "money"),
                column("remaining", "Remaining", "money"),
                column("people", "Beneficiaries reached", "number"),
                column("institutions", "Institutions reached", "number"),
                column("groups", "Households / groups reached", "number")
            ],
            rows: donationRows.map(({ donorId, ...row }) => row)
        }
    });

};


module.exports = {
    key: "donors",
    title: "Donors & funding",
    description: "Donors and donations: received, pledged, what each paid for and who it reached.",
    filters: ["program"],
    detail: "donor",
    generate,
    donationUse
};
