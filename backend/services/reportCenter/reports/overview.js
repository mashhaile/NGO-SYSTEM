// =====================================================
// ORGANIZATION OVERVIEW
// =====================================================
//
// The year (or period) at a glance, for a board or an
// annual report: the key figures of every area. Each
// figure is taken from the area's own report, so the
// overview and the reports always agree.
//
// =====================================================

const { column, section, summaryItem, buildReport, hasPermission } = require("../core");


const pick = (report, label) => report?.summary.find(item => item.label === label);

const rowOf = (area, report, label, measure = label) => {
    const item = pick(report, label);
    return item ? { area, measure, value: item.value, format: item.format, currency: item.currency, note: item.note || "" } : null;
};


const generate = async (query, context, period) => {

    const money = hasPermission(context, "budget.read");

    const run = (name) => require(`./${name}`).generate(query, context, period);

    const [people, programs, activities, delivery, enterprises, donors, budgets] = await Promise.all([
        run("beneficiaries"),
        run("programs"),
        run("activities"),
        run("serviceDelivery"),
        run("enterprises"),
        run("donors"),
        money ? run("budgets") : Promise.resolve(null)
    ]);

    const results = [
        rowOf("People", people, "Registered beneficiaries"),
        rowOf("People", people, "Reached by services"),
        rowOf("People", people, "Female", "Female beneficiaries"),
        rowOf("People", people, "With a disability", "Beneficiaries with a disability"),
        rowOf("Programs", programs, "Programs"),
        rowOf("Programs", programs, "Projects"),
        rowOf("Activities", activities, "Activities"),
        rowOf("Activities", activities, "Sessions held"),
        rowOf("Activities", activities, "Participants", "Training participants"),
        rowOf("Activities", activities, "Attendance rate"),
        rowOf("Services", delivery, "Deliveries"),
        rowOf("Services", delivery, "Value delivered"),
        rowOf("Services", delivery, "Given to people"),
        rowOf("Services", delivery, "Institutions reached"),
        rowOf("Services", delivery, "To institutions", "Value to institutions"),
        rowOf("Services", delivery, "Households and groups reached"),
        rowOf("Services", delivery, "To households and groups", "Value to households and groups"),
        rowOf("Enterprises", enterprises, "Enterprises"),
        rowOf("Enterprises", enterprises, "Members", "Enterprise members"),
        rowOf("Enterprises", enterprises, "Support to members"),
        rowOf("Funding", donors, "Donors"),
        rowOf("Funding", donors, "Received", "Funding received"),
        rowOf("Funding", donors, "Pledged, not yet received", "Pledged"),
        ...(budgets
            ? [
                rowOf("Budget", budgets, budgets.summary.find(item => item.label.startsWith("Budget for FY"))?.label, "Budget for the year"),
                rowOf("Budget", budgets, "Spent", "Spent"),
                rowOf("Budget", budgets, "Remaining")
            ]
            : [])
    ].filter(Boolean);

    // the headline figures
    const headline = [
        pick(people, "Reached by services") && { ...pick(people, "Reached by services"), label: "People reached" },
        pick(delivery, "Value delivered"),
        pick(delivery, "Institutions reached"),
        pick(activities, "Participants") && { ...pick(activities, "Participants"), label: "Training participants" },
        pick(programs, "Projects") && { ...pick(programs, "Projects"), label: "Projects" },
        pick(donors, "Received") && { ...pick(donors, "Received"), label: "Funding received" },
        ...(budgets ? [{ ...budgets.summary.find(item => item.label === "Spent"), label: "Spent" }] : [])
    ].filter(Boolean).map(item => summaryItem(item.label, item.value, item.format, { currency: item.currency, note: item.note }));

    const programSection = programs.sections.find(item => item.key === "programs");
    const monthSection = delivery.sections.find(item => item.key === "month");
    const genderSection = people.sections.find(item => item.key === "gender");

    return buildReport({
        key: "overview",
        title: "Organization overview",
        description: "The period at a glance: people, programs, activities, services, enterprises, funding" + (money ? " and spending." : "."),
        period,
        summary: headline,
        sections: [
            section("results", "Key results", [
                column("area", "Area"),
                column("measure", "Measure"),
                column("value", "Value"),
                column("note", "Note")
            ], results.map(row => ({
                ...row,
                value: row.format === "money"
                    ? `${row.currency ? `${row.currency} ` : ""}${Number(row.value).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
                    : row.format === "percent" ? `${row.value}%`
                        : row.format === "number" ? Number(row.value).toLocaleString("en-US") : row.value
            }))),
            programSection && { ...programSection, title: "Programs" },
            monthSection && { ...monthSection, key: "deliveryMonth", title: "Services by month" },
            genderSection && { ...genderSection, key: "peopleGender", title: "People by gender" }
        ].filter(Boolean)
    });

};


module.exports = {
    key: "overview",
    title: "Organization overview",
    description: "The year at a glance: people, programs, services, enterprises and funding.",
    filters: [],
    generate
};
