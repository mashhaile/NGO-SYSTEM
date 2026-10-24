// =====================================================
// PROGRAM / PROJECT (detail reports)
// =====================================================
//
// One program or project: its people, deliveries,
// activities, the donations for it, and (for roles that
// see budgets) its budget and spending.
//
// =====================================================

const Program = require("../../../models/program");
const Project = require("../../../models/Project");
const Activity = require("../../../models/Activity");
const ActivityRun = require("../../../models/ActivityRun");
const Enrollment = require("../../../models/enrollment");
const Donation = require("../../../models/donation");
const Expense = require("../../../models/Expense");

const { getBudgetFigures } = require("../../budgetFigures");

const {
    scope, formatTotals, objectId, toId, round2, toNumber, fullName, lookupText, groupRows,
    summaryItem, column, section, buildReport, hasPermission, notFound
} = require("../core");

const { inPeriod } = require("../period");
const { loadDeliveries, loadServedLinks, serviceName, quantityText, recipientsOf } = require("../data");


const addTo = (totals, currency, amount) => {
    const key = currency || "ETB";
    totals[key] = round2((totals[key] || 0) + toNumber(amount));
    return totals;
};


const build = async (level, id, query, context, period) => {

    const { organizationId } = context;
    const money = hasPermission(context, "budget.read");
    const isProgram = level === "program";

    const record =
        objectId(id) &&
        (isProgram
            ? await Program.findOne(scope(organizationId, { _id: objectId(id) })).lean()
            : await Project.findOne(scope(organizationId, { _id: objectId(id) }))
                .populate("program", "programCode name")
                .populate("donor", "name")
                .populate("projectManager", "firstName lastName name")
                .lean());

    if (!record) throw notFound(isProgram ? "Program" : "Project");

    const projects =
        isProgram
            ? await Project.find(scope(organizationId, { program: record._id })).select("projectCode name status startDate endDate").sort({ projectCode: 1 }).lean()
            : [record];

    const projectIds = projects.map(project => project._id);
    const own = isProgram ? { program: record._id } : { project: record._id };

    const deliveries = await loadDeliveries(organizationId, period, own);
    const links = await loadServedLinks(organizationId, deliveries);

    const people = new Map();
    for (const link of links) people.set(link.beneficiaryId, (people.get(link.beneficiaryId) || 0) + link.value);

    const Beneficiary = require("../../../models/Beneficiary");
    const reachedPeople =
        people.size
            ? await Beneficiary.find(scope(organizationId, { _id: { $in: [...people.keys()].map(objectId) } }))
                .select("gender").populate("gender", "value").lean()
            : [];

    const enrollments =
        isProgram
            ? await Enrollment.find(scope(organizationId, { program: record._id })).select("status").lean()
            : [];

    const activityDate = inPeriod(period);
    const activities =
        await Activity.find(scope(organizationId, { project: { $in: projectIds }, ...(activityDate ? { activityDate } : {}) }))
            .select("activityCode name activityType activityDate status targetParticipants project")
            .sort({ activityDate: 1 })
            .lean();

    const runs =
        await ActivityRun.find(scope(organizationId, { project: { $in: projectIds } }))
            .select("runCode name startDate endDate status activity")
            .populate("activity", "name")
            .sort({ startDate: 1 })
            .lean();

    const donationDate = inPeriod(period);
    const donations =
        await Donation.find(scope(organizationId, {
            ...(isProgram ? { $or: [{ program: record._id }, { project: { $in: projectIds } }] } : { project: record._id }),
            ...(donationDate ? { donationDate } : {})
        }))
            .populate("donor", "name")
            .sort({ donationDate: 1 })
            .lean();

    const figures = money ? await getBudgetFigures(organizationId, isProgram ? { programIds: [record._id] } : { projectIds: [record._id] }) : null;
    const figure = figures ? (isProgram ? figures.programs?.[toId(record._id)] : figures.projects?.[toId(record._id)]) : null;

    const expenseDate = inPeriod(period);
    const expenses =
        money
            ? await Expense.find(scope(organizationId, { status: "Approved", project: { $in: projectIds }, ...(expenseDate ? { expenseDate } : {}) }))
                .select("category budgetAmount amount")
                .lean()
            : [];

    const received = donations.filter(donation => donation.status === "Received")
        .reduce((totals, donation) => addTo(totals, donation.currency, donation.amount), {});

    const valueDelivered = round2(deliveries.reduce((sum, delivery) => sum + toNumber(delivery.totalAmount), 0));

    const fields =
        isProgram
            ? [
                { label: "Code", value: record.programCode },
                { label: "Category", value: record.category },
                { label: "Status", value: record.status },
                { label: "Start", value: record.startDate, format: "date" },
                { label: "End", value: record.endDate, format: "date" },
                { label: "Target people", value: record.targetBeneficiaries }
            ]
            : [
                { label: "Code", value: record.projectCode },
                { label: "Program", value: record.program?.name },
                { label: "Status", value: record.status },
                { label: "Start", value: record.startDate, format: "date" },
                { label: "End", value: record.endDate, format: "date" },
                { label: "Donor", value: record.donor?.name },
                { label: "Project manager", value: record.projectManager ? (record.projectManager.name || fullName(record.projectManager)) : "" }
            ];

    if (money && figure) {
        fields.push(
            { label: "Budget", value: `${figure.budgetCode || ""} (${figure.status})` },
            { label: "Approved budget", value: `${figure.currency} ${round2(figure.approvedAmount).toLocaleString("en-US", { minimumFractionDigits: 2 })}` }
        );
    }

    return buildReport({
        key: level,
        title: record.name,
        description: isProgram
            ? `Program ${record.programCode}: projects, people, deliveries, activities and funding.`
            : `Project ${record.projectCode}: people, deliveries, activities and funding.`,
        period,
        record: { fields },
        summary: [
            ...(isProgram ? [summaryItem("Projects", projects.length), summaryItem("People enrolled", enrollments.length)] : []),
            summaryItem("Beneficiaries reached", people.size),
            summaryItem("Institutions reached", recipientsOf(deliveries).institutions.count, "number", { note: recipientsOf(deliveries).institutions.names.join(", ") || undefined }),
            summaryItem("Households and groups reached", recipientsOf(deliveries).groups.count, "number", { note: recipientsOf(deliveries).groups.names.join(", ") || undefined }),
            summaryItem("Deliveries", deliveries.length),
            summaryItem("Value delivered", valueDelivered, "money", { currency: "ETB" }),
            summaryItem("Activities", activities.length),
            summaryItem("Funding received", formatTotals(received), "text"),
            ...(money && figure
                ? [
                    summaryItem("Spent to date", round2(figure.spent), "money", { currency: figure.currency }),
                    summaryItem("Remaining", round2(figure.remaining), "money", { currency: figure.currency })
                ]
                : [])
        ],
        sections: [
            isProgram
                ? section("projects", "Projects", [
                    column("code", "Code"),
                    column("name", "Project"),
                    column("status", "Status"),
                    column("start", "Start", "date"),
                    column("end", "End", "date"),
                    column("deliveries", "Deliveries", "number"),
                    column("value", "Value delivered", "money", { currency: "ETB" })
                ], projects.map(project => {
                    const ownDeliveries = deliveries.filter(delivery => toId(delivery.project) === toId(project._id));
                    return {
                        id: toId(project._id),
                        code: project.projectCode,
                        name: project.name,
                        status: project.status,
                        start: project.startDate,
                        end: project.endDate,
                        deliveries: ownDeliveries.length,
                        value: round2(ownDeliveries.reduce((sum, delivery) => sum + toNumber(delivery.totalAmount), 0))
                    };
                }), { link: { kind: "project", idKey: "id" } })
                : null,
            section("gender", "People reached, by gender", [
                column("label", "Gender"),
                column("people", "People", "number")
            ], groupRows(reachedPeople, person => lookupText(person.gender) || "Not specified", { people: () => 1 }),
            { chart: { type: "pie", x: "label", series: ["people"] } }),
            section("services", "What was delivered", [
                column("label", "Service"),
                column("quantity", "Quantity"),
                column("deliveries", "Deliveries", "number"),
                column("value", "Value", "money", { currency: "ETB" })
            ], (() => {
                const map = new Map();
                for (const delivery of deliveries) for (const item of delivery.items || []) {
                    const key = `${serviceName(item)}|${item.unit?.value || ""}`;
                    const row = map.get(key) || { label: serviceName(item), unit: item.unit, sample: item, quantity: 0, money: 0, deliveries: new Set(), value: 0 };
                    row.quantity += toNumber(item.quantity);
                    row.money += toNumber(item.totalCost);
                    row.deliveries.add(toId(delivery._id));
                    row.value += toNumber(item.totalCost);
                    map.set(key, row);
                }
                return [...map.values()]
                    .sort((a, b) => b.value - a.value)
                    .map(row => ({
                        label: row.label,
                        quantity: quantityText({ ...row.sample, quantity: row.quantity, totalCost: row.money }),
                        deliveries: row.deliveries.size,
                        value: round2(row.value)
                    }));
            })()),
            section("deliveries", "Deliveries", [
                column("date", "Date", "date"),
                column("number", "Delivery"),
                column("activity", "Activity"),
                column("recipient", "Recipient"),
                column("people", "People", "number"),
                column("value", "Value", "money", { currency: "ETB" })
            ], deliveries.map(delivery => ({
                id: toId(delivery._id),
                date: delivery.deliveryDate,
                number: delivery.deliveryNumber,
                activity: delivery.activity?.name || "",
                recipient: delivery.recipientType === "Individual" ? "Individuals" : `${delivery.recipientType}${delivery.recipientName ? `: ${delivery.recipientName}` : ""}`,
                people: links.filter(link => toId(link.serviceDelivery._id) === toId(delivery._id)).length,
                value: round2(delivery.totalAmount)
            })), { link: { kind: "delivery", idKey: "id" }, total: { value: valueDelivered } }),
            section("activities", "Activities and runs", [
                column("date", "Date", "date"),
                column("name", "Activity / run"),
                column("type", "Type"),
                column("status", "Status")
            ], [
                ...activities.map(activity => ({ date: activity.activityDate, name: activity.name, type: activity.activityType, status: activity.status })),
                ...runs.map(run => ({ id: toId(run._id), date: run.startDate, name: `${run.activity?.name ? `${run.activity.name}: ` : ""}${run.name}`, type: "Run", status: run.status }))
            ].sort((a, b) => new Date(a.date) - new Date(b.date)), { link: { kind: "activityRun", idKey: "id" } }),
            section("donations", "Donations", [
                column("date", "Date", "date"),
                column("code", "Donation"),
                column("title", "Title"),
                column("donor", "Donor"),
                column("status", "Status"),
                column("amount", "Amount", "money"),
                column("currency", "Currency")
            ], donations.map(donation => ({
                id: toId(donation._id),
                date: donation.donationDate,
                code: donation.donationCode,
                title: donation.title,
                donor: donation.donor?.name || "",
                status: donation.status,
                amount: round2(donation.amount),
                currency: donation.currency || "ETB"
            })), { link: { kind: "donation", idKey: "id" } }),
            money
                ? section("spending", "Spending in the period, by category", [
                    column("label", "Category"),
                    column("expenses", "Expenses", "number"),
                    column("amount", "Amount", "money", { currency: figure?.currency || "ETB" })
                ], groupRows(expenses, expense => expense.category, { amount: expense => toNumber(expense.budgetAmount ?? expense.amount), expenses: () => 1 }))
                : null
        ]
    });

};


module.exports = [
    { kind: "program", title: "Program", generate: (id, query, context, period) => build("program", id, query, context, period) },
    { kind: "project", title: "Project", generate: (id, query, context, period) => build("project", id, query, context, period) }
];
