// =====================================================
// SERVICE DELIVERY REPORT
// =====================================================
//
// What was delivered (goods, cash, training), where, to
// whom, how much of it reached people, and which donation
// paid for it. Replaces the Service Delivery and Monthly
// Service reports.
//
//   Value delivered   = cost of everything delivered
//   Given to people   = each person's own share, summed
//   To groups         = deliveries to a household, group
//                       or institution as a whole
//   Not given out     = individual deliveries' value no
//                       one received (stock left, cash
//                       not shared out)
//
// Filters: program, project, region
//
// =====================================================

const {
    objectId, toId, round2, toNumber, percent, locationText, groupRows,
    summaryItem, column, section, buildReport
} = require("../core");

const { monthKey, monthName } = require("../period");
const { loadDeliveries, loadServedLinks, serviceName, quantityText, isMoneyUnit, recipientsOf, countText, INSTITUTION, HOUSEHOLD_OR_GROUP } = require("../data");


const generate = async (query, context, period) => {

    const { organizationId } = context;

    const filter = {};
    if (objectId(query.program)) filter.program = objectId(query.program);
    if (objectId(query.project)) filter.project = objectId(query.project);
    if (query.region) filter.$or = [{ region: query.region }, { regionCode: query.region }];

    const deliveries = await loadDeliveries(organizationId, period, filter);
    const links = await loadServedLinks(organizationId, deliveries);

    // ---------- per delivery ----------
    const rows = deliveries.map(delivery => {
        const own = links.filter(link => toId(link.serviceDelivery._id) === toId(delivery._id));
        const individual = (delivery.recipientType || "Individual") === "Individual";
        const value = toNumber(delivery.totalAmount);
        const toPeople = round2(own.reduce((sum, link) => sum + link.value, 0));
        return {
            delivery,
            people: own.map(link => link.beneficiaryId),
            id: toId(delivery._id),
            number: delivery.deliveryNumber,
            date: delivery.deliveryDate,
            program: delivery.program?.name || "",
            project: delivery.project?.name || "",
            activity: delivery.activity?.name || "",
            location: locationText(delivery) || delivery.deliveryLocation || "",
            recipient: individual ? "Individuals" : `${delivery.recipientType}${delivery.recipientName ? `: ${delivery.recipientName}` : ""}`,
            services: (delivery.items || []).map(item => `${serviceName(item)} (${quantityText(item)})`).join("; "),
            peopleCount: own.length,
            value: round2(value),
            toPeople: individual ? toPeople : 0,
            toGroups: individual ? 0 : round2(value),
            toInstitutions: delivery.recipientType === "Institution" ? round2(value) : 0,
            toHouseholds: ["Household", "Group / Community"].includes(delivery.recipientType) ? round2(value) : 0,
            notGiven: individual ? round2(Math.max(value - toPeople, 0)) : 0
        };
    });

    const total = (key) => round2(rows.reduce((sum, row) => sum + row[key], 0));

    // institutions and households / groups reached as a whole
    const { institutions, groups } = recipientsOf(deliveries);
    const valueDelivered = total("value");
    const people = new Set(links.map(link => link.beneficiaryId));

    // ---------- items (what was delivered) ----------
    const items = [];
    for (const row of rows) for (const item of row.delivery.items || []) items.push({ item, row });

    const serviceRows = (() => {
        const map = new Map();
        for (const { item, row } of items) {
            const key = `${serviceName(item)}|${item.unit?.value || ""}`;
            const entry = map.get(key) || {
                label: serviceName(item),
                category: item.serviceCategory?.value || "",
                sample: item,
                quantity: 0,
                money: 0,
                deliveries: new Set(),
                people: new Set(),
                institutions: new Set(),
                groups: new Set(),
                value: 0
            };
            entry.quantity += toNumber(item.quantity);
            entry.money += toNumber(item.totalCost);
            entry.value += toNumber(item.totalCost);
            entry.deliveries.add(row.id);
            for (const person of row.people) entry.people.add(person);
            const recipient = String(row.delivery.recipientName || row.number).trim().toLowerCase();
            if (INSTITUTION.includes(row.delivery.recipientType)) entry.institutions.add(recipient);
            if (HOUSEHOLD_OR_GROUP.includes(row.delivery.recipientType)) entry.groups.add(recipient);
            map.set(key, entry);
        }
        return [...map.values()].sort((a, b) => b.value - a.value).map(entry => ({
            label: entry.label,
            category: entry.category,
            quantity: quantityText({ ...entry.sample, quantity: entry.quantity, totalCost: entry.money }),
            kind: isMoneyUnit(entry.sample.unit) ? "Money" : "Goods / service",
            deliveries: entry.deliveries.size,
            people: entry.people.size,
            institutions: entry.institutions.size,
            groups: entry.groups.size,
            value: round2(entry.value)
        }));
    })();

    const byRows = (keyOf) => {
        const map = new Map();
        for (const row of rows) {
            const key = keyOf(row) || "Not specified";
            const entry = map.get(key) || { label: key, deliveries: 0, people: new Set(), value: 0, toPeople: 0, toInstitutions: 0, toHouseholds: 0 };
            entry.deliveries += 1;
            entry.value += row.value;
            entry.toPeople += row.toPeople;
            entry.toInstitutions += row.toInstitutions;
            entry.toHouseholds += row.toHouseholds;
            for (const person of row.people) entry.people.add(person);
            map.set(key, entry);
        }
        return [...map.values()].map(entry => ({ ...entry, people: entry.people.size, value: round2(entry.value), toPeople: round2(entry.toPeople), toInstitutions: round2(entry.toInstitutions), toHouseholds: round2(entry.toHouseholds) }));
    };

    const breakdownColumns = (first) => [
        column("label", first),
        column("deliveries", "Deliveries", "number"),
        column("people", "People reached", "number"),
        column("value", "Value delivered", "money", { currency: "ETB" }),
        column("toPeople", "Given to people", "money", { currency: "ETB" }),
        column("toInstitutions", "To institutions", "money", { currency: "ETB" }),
        column("toHouseholds", "To households and groups", "money", { currency: "ETB" })
    ];

    const monthRows = (() => {
        const map = new Map();
        for (const row of rows) {
            const key = monthKey(row.date);
            const entry = map.get(key) || { key, deliveries: 0, people: new Set(), value: 0, toPeople: 0, toInstitutions: 0, toHouseholds: 0 };
            entry.deliveries += 1;
            entry.value += row.value;
            entry.toPeople += row.toPeople;
            entry.toInstitutions += row.toInstitutions;
            entry.toHouseholds += row.toHouseholds;
            for (const person of row.people) entry.people.add(person);
            map.set(key, entry);
        }
        return [...map.values()].sort((a, b) => a.key.localeCompare(b.key))
            .map(entry => ({ label: monthName(entry.key), deliveries: entry.deliveries, people: entry.people.size, value: round2(entry.value), toPeople: round2(entry.toPeople), toInstitutions: round2(entry.toInstitutions), toHouseholds: round2(entry.toHouseholds) }));
    })();

    // ---------- funding ----------
    const fundingRows = groupRows(items, ({ item }) =>
        item.donation ? `${item.donation.donationCode || ""} ${item.donation.title || ""}`.trim() : "Not linked to a donation",
        { value: ({ item }) => item.totalCost, items: () => 1 });
    for (const row of fundingRows) {
        const sample = items.find(({ item }) => (item.donation ? `${item.donation.donationCode || ""} ${item.donation.title || ""}`.trim() : "Not linked to a donation") === row.label);
        row.donor = sample?.item.donor?.name || (sample?.item.donation ? "" : "—");
        row.id = sample?.item.donation ? toId(sample.item.donation._id) : "";
    }

    const untraced = round2(items.filter(({ item }) => !item.donation).reduce((sum, { item }) => sum + toNumber(item.totalCost), 0));

    return buildReport({
        key: "serviceDelivery",
        title: "Service delivery",
        description: "What was delivered, where and to whom, how much reached people (their own share), and which donation paid.",
        period,
        summary: [
            summaryItem("Deliveries", rows.length),
            summaryItem("Beneficiaries reached", people.size),
            summaryItem("Value delivered", valueDelivered, "money", { currency: "ETB" }),
            summaryItem("Given to people", total("toPeople"), "money", { currency: "ETB", note: `${percent(total("toPeople"), valueDelivered)}% of the value` }),
            summaryItem("Institutions reached", institutions.count, "number", { note: `ETB ${institutions.value.toLocaleString("en-US", { minimumFractionDigits: 2 })}` }),
            summaryItem("To institutions", institutions.value, "money", { currency: "ETB", note: countText(institutions.count, "institution", "institutions") }),
            summaryItem("Households and groups reached", groups.count, "number", { note: `ETB ${groups.value.toLocaleString("en-US", { minimumFractionDigits: 2 })}` }),
            summaryItem("To households and groups", groups.value, "money", { currency: "ETB", note: countText(groups.count, "household or group", "households or groups") }),
            summaryItem("Not given out", total("notGiven"), "money", { currency: "ETB", note: "on individual deliveries" }),
            summaryItem("Not linked to a donation", untraced, "money", { currency: "ETB", note: untraced ? "appears in no donor's trace" : "every item is traced" })
        ],
        sections: [
            section("services", "What was delivered", [
                column("label", "Service"),
                column("category", "Category"),
                column("kind", "Kind"),
                column("quantity", "Quantity"),
                column("deliveries", "Deliveries", "number"),
                column("people", "Beneficiaries", "number"),
                column("institutions", "Institutions", "number"),
                column("groups", "Households / groups", "number"),
                column("value", "Value", "money", { currency: "ETB" })
            ], serviceRows, { chart: { type: "bar", x: "label", series: ["value"], yLabel: "ETB" }, total: { value: valueDelivered } }),
            section("month", "By month", breakdownColumns("Month"), monthRows,
                { chart: { type: "bar", x: "label", series: ["toPeople", "toInstitutions", "toHouseholds"], stacked: true, yLabel: "ETB" } }),
            section("program", "By program", breakdownColumns("Program"), byRows(row => row.program).sort((a, b) => b.value - a.value)),
            section("project", "By project", breakdownColumns("Project"), byRows(row => row.project).sort((a, b) => b.value - a.value)),
            section("location", "By location", breakdownColumns("Woreda, zone, region"), byRows(row => row.location).sort((a, b) => b.value - a.value)),
            section("recipient", "By recipient", breakdownColumns("Recipient"), byRows(row => row.delivery.recipientType || "Individual").sort((a, b) => b.value - a.value)),
            section("funding", "Who paid", [
                column("label", "Donation"),
                column("donor", "Donor"),
                column("items", "Items", "number"),
                column("value", "Value", "money", { currency: "ETB" })
            ], fundingRows, { link: { kind: "donation", idKey: "id" } })
        ],
        details: {
            title: "Deliveries",
            link: { kind: "delivery", idKey: "id" },
            columns: [
                column("number", "Delivery"),
                column("date", "Date", "date"),
                column("program", "Program"),
                column("project", "Project"),
                column("location", "Location"),
                column("recipient", "Recipient"),
                column("services", "Services"),
                column("peopleCount", "People", "number"),
                column("value", "Value", "money", { currency: "ETB" }),
                column("toPeople", "Given to people", "money", { currency: "ETB" }),
                column("notGiven", "Not given out", "money", { currency: "ETB" })
            ],
            rows: rows.map(({ delivery, people: _people, ...row }) => row)
        }
    });

};


module.exports = {
    key: "serviceDelivery",
    title: "Service delivery",
    description: "Goods, cash and services delivered: where, to whom, how much reached people, who paid.",
    filters: ["program", "project", "region"],
    generate
};
