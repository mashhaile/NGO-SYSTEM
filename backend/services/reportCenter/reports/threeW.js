// =====================================================
// 3W / 4W REPORT (humanitarian response)
// =====================================================
//
// Who does What, Where, When: the format the government
// and the humanitarian clusters ask every organization for.
// One row per place (Region › Zone › Woreda), sector
// (service category), activity (service type) and project:
//
//   Who     the organization, project, donor
//   What    sector, activity, quantity delivered
//   Where   region, zone, woreda
//   When    first and last delivery in the period
//   Reached people (each counted once per row): women,
//           men, girls, boys (under 18), and households
//           (deliveries to a household; its people from
//           the household size when known)
//
// Delivered deliveries only; people marked Missed are not
// reached. Deliveries saved although the same person had
// already received the same service are listed with the
// reason given. Needs service.read; the humanitarian module
// must be on.
//
// Filters: program, project type, project, region
//
// =====================================================

const Beneficiary = require("../../../models/Beneficiary");
const Organization = require("../../../models/organization");

const {
    objectId, toId, round2, toNumber, ageOf,
    summaryItem, column, section, buildReport, projectIn
} = require("../core");

const { loadDeliveries, loadServedLinks, serviceName, unitName } = require("../data");


const CHILD_UNDER = 18;

const placeOf = (delivery) => ({
    region: delivery.region || "Not set",
    zone: delivery.zone || "",
    woreda: delivery.woreda || ""
});

const sexOf = (person) => {
    const value = String(person?.gender?.value || "").toLowerCase();
    return value === "female" ? "F" : value === "male" ? "M" : "";
};


const generate = async (query, context, period) => {

    const { organizationId } = context;

    const filter = {};
    if (objectId(query.program)) filter.program = objectId(query.program);
    if (objectId(query.project)) filter.project = projectIn(query);
    if (query.region) filter.$or = [{ region: query.region }, { regionCode: query.region }];

    const [deliveries, organization] =
        await Promise.all([
            loadDeliveries(organizationId, period, filter),
            Organization.findById(organizationId).select("name").lean()
        ]);

    // each project with its donor and type
    const projects =
        await require("../../../models/Project").find({ _id: { $in: [...new Set(deliveries.map(delivery => toId(delivery.project?._id)).filter(Boolean))] } })
            .select("projectCode name donor projectType")
            .populate("donor", "name")
            .populate("projectType", "value")
            .lean();
    const projectById = new Map(projects.map(project => [toId(project._id), project]));
    const populated = deliveries.map(delivery => ({ ...delivery, project: projectById.get(toId(delivery.project?._id)) || delivery.project }));

    const links = (await loadServedLinks(organizationId, populated)).filter(link => link.status !== "Missed");

    const people =
        await Beneficiary.find({ _id: { $in: [...new Set(links.map(link => link.beneficiaryId))] } })
            .select("gender dateOfBirth age householdSize")
            .populate("gender", "value")
            .lean();

    const personById = new Map(people.map(person => [toId(person._id), person]));

    // ---------- rows: place x sector x activity x project ----------
    const rows = new Map();

    for (const delivery of populated) {

        const place = placeOf(delivery);
        const own = links.filter(link => toId(link.serviceDelivery._id) === toId(delivery._id));
        const household = delivery.recipientType === "Household";

        for (const item of delivery.items || []) {

            const sector = item.serviceCategory?.value || "Other";
            const activity = serviceName(item);
            const key = [place.region, place.zone, place.woreda, sector, activity, toId(delivery.project?._id)].join("|");

            const row = rows.get(key) || {
                ...place,
                organization: organization?.name || "",
                project: delivery.project?.name || "-",
                projectType: delivery.project?.projectType?.value || "",
                donor: item.donor?.name || delivery.project?.donor?.name || "",
                sector,
                activity,
                unit: unitName(item.unit),
                quantity: 0,
                deliveries: new Set(),
                people: new Set(),
                households: new Set(),
                first: null,
                last: null
            };

            row.quantity = round2(row.quantity + toNumber(item.quantity));
            row.deliveries.add(toId(delivery._id));
            for (const link of own) {
                row.people.add(link.beneficiaryId);
                if (household) row.households.add(link.beneficiaryId);
            }
            if (household && !own.length) row.households.add(`delivery:${toId(delivery._id)}`);
            if (!row.first || delivery.deliveryDate < row.first) row.first = delivery.deliveryDate;
            if (!row.last || delivery.deliveryDate > row.last) row.last = delivery.deliveryDate;

            rows.set(key, row);

        }

    }

    const counts = (ids) => {
        const result = { women: 0, men: 0, girls: 0, boys: 0, unknown: 0 };
        for (const id of ids) {
            const person = personById.get(id);
            const sex = sexOf(person);
            const age = ageOf(person);
            const child = age !== null && age < CHILD_UNDER;
            if (sex === "F") result[child ? "girls" : "women"] += 1;
            else if (sex === "M") result[child ? "boys" : "men"] += 1;
            else result.unknown += 1;
        }
        return result;
    };

    const householdPeople = (ids) =>
        [...ids].reduce((sum, id) => sum + (toNumber(personById.get(id)?.householdSize) || 0), 0);

    const tableRows =
        [...rows.values()]
            .map(row => {
                const split = counts(row.people);
                return {
                    organization: row.organization,
                    sector: row.sector,
                    activity: row.activity,
                    region: row.region,
                    zone: row.zone,
                    woreda: row.woreda,
                    project: row.project,
                    projectType: row.projectType,
                    donor: row.donor,
                    start: row.first,
                    end: row.last,
                    quantity: row.quantity,
                    unit: row.unit,
                    deliveries: row.deliveries.size,
                    people: row.people.size,
                    ...split,
                    households: row.households.size,
                    householdPeople: householdPeople([...row.households].filter(id => !id.startsWith("delivery:")))
                };
            })
            .sort((a, b) => [a.region, a.zone, a.woreda, a.sector, a.activity].join("|").localeCompare([b.region, b.zone, b.woreda, b.sector, b.activity].join("|")));

    // ---------- by sector, by woreda (people once per group) ----------
    const groupBy = (keyOf) => {
        const map = new Map();
        for (const delivery of populated) {
            const own = links.filter(link => toId(link.serviceDelivery._id) === toId(delivery._id));
            for (const item of delivery.items || []) {
                const key = keyOf(delivery, item);
                const entry = map.get(key) || { label: key, deliveries: new Set(), people: new Set() };
                entry.deliveries.add(toId(delivery._id));
                for (const link of own) entry.people.add(link.beneficiaryId);
                map.set(key, entry);
            }
        }
        return [...map.values()]
            .map(entry => ({ label: entry.label, deliveries: entry.deliveries.size, people: entry.people.size, ...counts(entry.people) }))
            .sort((a, b) => b.people - a.people);
    };

    const sectorRows = groupBy((delivery, item) => item.serviceCategory?.value || "Other");
    const woredaRows = groupBy((delivery) => {
        const place = placeOf(delivery);
        return [place.region, place.zone, place.woreda].filter(Boolean).join(" › ");
    });

    // ---------- repeated deliveries (confirmed with a reason) ----------
    const repeatRows =
        populated
            .filter(delivery => delivery.duplicateConfirmed)
            .map(delivery => ({
                id: toId(delivery._id),
                number: delivery.deliveryNumber,
                date: delivery.deliveryDate,
                project: delivery.project?.name || "",
                services: (delivery.items || []).map(serviceName).join(", "),
                reason: delivery.duplicateReason || "-"
            }));

    const everyone = new Set(links.map(link => link.beneficiaryId));
    const all = counts(everyone);
    const allHouseholds = new Set(tableRows.length ? [...rows.values()].flatMap(row => [...row.households]) : []);

    const peopleColumns = [
        column("people", "People", "number"),
        column("women", "Women", "number"),
        column("men", "Men", "number"),
        column("girls", "Girls", "number"),
        column("boys", "Boys", "number")
    ];

    return buildReport({
        key: "threeW",
        title: "3W / 4W: who, what, where, when",
        description: `${organization?.name || "The organization"}: what was delivered, where and to whom in the period, per woreda, sector and activity. People are counted once per row; children are under ${CHILD_UNDER}.`,
        period,
        summary: [
            summaryItem("Deliveries", populated.length),
            summaryItem("People reached", everyone.size),
            summaryItem("Women", all.women),
            summaryItem("Men", all.men),
            summaryItem("Girls", all.girls),
            summaryItem("Boys", all.boys),
            summaryItem("Households reached", allHouseholds.size),
            summaryItem("Woredas", new Set(tableRows.map(row => `${row.region}|${row.zone}|${row.woreda}`)).size),
            summaryItem("Sectors", sectorRows.length),
            summaryItem("Repeated deliveries (confirmed)", repeatRows.length)
        ],
        sections: [
            section("sector", "By sector", [column("label", "Sector"), column("deliveries", "Deliveries", "number"), ...peopleColumns], sectorRows,
                { chart: { type: "bar", x: "label", series: ["women", "men", "girls", "boys"], stacked: true } }),
            section("woreda", "By woreda", [column("label", "Region › Zone › Woreda"), column("deliveries", "Deliveries", "number"), ...peopleColumns], woredaRows),
            repeatRows.length
                ? section("repeats", "Repeated deliveries (confirmed with a reason)", [
                    column("number", "Delivery"),
                    column("date", "Date", "date"),
                    column("project", "Project"),
                    column("services", "Services"),
                    column("reason", "Reason given")
                ], repeatRows, { link: { kind: "delivery", idKey: "id" }, note: "The same person had already received the same service in the period set in Humanitarian Setup." })
                : null
        ],
        details: {
            title: "3W / 4W table",
            columns: [
                column("organization", "Organization"),
                column("sector", "Sector"),
                column("activity", "Activity"),
                column("region", "Region"),
                column("zone", "Zone"),
                column("woreda", "Woreda"),
                column("project", "Project"),
                column("projectType", "Project type"),
                column("donor", "Donor"),
                column("start", "From", "date"),
                column("end", "To", "date"),
                column("quantity", "Quantity", "number"),
                column("unit", "Unit"),
                column("deliveries", "Deliveries", "number"),
                ...peopleColumns,
                column("households", "Households", "number"),
                column("householdPeople", "People in households", "number")
            ],
            rows: tableRows
        }
    });

};


module.exports = {
    key: "threeW",
    title: "3W / 4W (who, what, where, when)",
    description: "For the government and the clusters: what was delivered where and to whom, per woreda, sector and activity, with women, men, girls, boys and households.",
    filters: ["program", "projectType", "project", "region"],
    permission: "service.read",
    generate
};
