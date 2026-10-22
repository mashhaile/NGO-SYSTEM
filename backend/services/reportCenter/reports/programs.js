// =====================================================
// PROGRAMS & PROJECTS REPORT
// =====================================================
//
// Each program and project: its people, what it
// delivered, the money received for it, its budget and
// spending. Replaces the Program, Program Impact and
// Project reports.
//
// Budget and spending show only for roles that can see
// budgets (budget.read).
//
// Filters: program, status
//
// =====================================================

const Program = require("../../../models/program");
const Project = require("../../../models/Project");
const Activity = require("../../../models/Activity");
const Enrollment = require("../../../models/enrollment");
const Donation = require("../../../models/donation");
const Expense = require("../../../models/Expense");

const { getBudgetFigures } = require("../../budgetFigures");

const {
    scope, formatTotals, objectId, toId, round2, toNumber, summaryItem, column, section, buildReport, hasPermission
} = require("../core");

const { inPeriod } = require("../period");
const { loadDeliveries, loadServedLinks } = require("../data");


// { ETB: 100, USD: 5 } → "ETB 100.00 + USD 5.00"
const addTo = (totals, currency, amount) => {
    const key = currency || "ETB";
    totals[key] = round2((totals[key] || 0) + toNumber(amount));
    return totals;
};


const generate = async (query, context, period) => {

    const { organizationId } = context;
    const money = hasPermission(context, "budget.read");

    // ---------- programs and projects ----------
    const programFilter = {};
    if (objectId(query.program)) programFilter._id = objectId(query.program);
    if (query.status) programFilter.status = query.status;

    const programs =
        await Program.find(scope(organizationId, programFilter))
            .select("programCode name status startDate endDate targetBeneficiaries")
            .sort({ programCode: 1 })
            .lean();

    const programIds = programs.map(program => program._id);

    const projects =
        await Project.find(scope(organizationId, { program: { $in: programIds } }))
            .select("program projectCode name status startDate endDate donor")
            .populate("donor", "name")
            .sort({ projectCode: 1 })
            .lean();

    const projectIds = projects.map(project => project._id);

    // ---------- people, deliveries, activities ----------
    const deliveries = await loadDeliveries(organizationId, period, { program: { $in: programIds } });
    const links = await loadServedLinks(organizationId, deliveries);

    const enrollments =
        await Enrollment.find(scope(organizationId, { program: { $in: programIds } }))
            .select("program beneficiary status")
            .lean();

    const activityDate = inPeriod(period);
    const activities =
        await Activity.find(scope(organizationId, {
            project: { $in: projectIds },
            ...(activityDate ? { activityDate } : {})
        }))
            .select("project status")
            .lean();

    // ---------- money ----------
    const donationDate = inPeriod(period);
    const donations =
        await Donation.find(scope(organizationId, {
            status: "Received",
            $or: [{ program: { $in: programIds } }, { project: { $in: projectIds } }],
            ...(donationDate ? { donationDate } : {})
        }))
            .select("program project amount currency")
            .lean();

    const figures = money ? await getBudgetFigures(organizationId, { programIds, projectIds }) : { programs: {}, projects: {} };

    const expenseDate = inPeriod(period);
    const expenses =
        money
            ? await Expense.find(scope(organizationId, {
                status: "Approved",
                project: { $in: projectIds },
                ...(expenseDate ? { expenseDate } : {})
            }))
                .select("project program budgetAmount budgetCurrency amount currency")
                .lean()
            : [];

    // ---------- per project ----------
    const projectRows = projects.map(project => {
        const id = toId(project._id);
        const own = deliveries.filter(delivery => toId(delivery.project) === id);
        const ownIds = new Set(own.map(delivery => toId(delivery._id)));
        const people = new Set(links.filter(link => ownIds.has(toId(link.serviceDelivery._id))).map(link => link.beneficiaryId));
        const figure = figures.projects?.[id];
        const spentInPeriod = expenses.filter(expense => toId(expense.project) === id)
            .reduce((sum, expense) => sum + toNumber(expense.budgetAmount ?? expense.amount), 0);
        const funding = donations.filter(donation => toId(donation.project) === id)
            .reduce((totals, donation) => addTo(totals, donation.currency, donation.amount), {});
        return {
            id,
            programId: toId(project.program),
            code: project.projectCode,
            name: project.name,
            status: project.status,
            start: project.startDate,
            end: project.endDate,
            donor: project.donor?.name || "",
            activities: activities.filter(activity => toId(activity.project) === id).length,
            deliveries: own.length,
            reached: people.size,
            value: round2(own.reduce((sum, delivery) => sum + toNumber(delivery.totalAmount), 0)),
            funding: formatTotals(funding),
            budgetCurrency: figure?.currency || "",
            approved: figure ? round2(figure.approvedAmount) : null,
            spentInPeriod: round2(spentInPeriod),
            spentToDate: figure ? round2(figure.spent) : null,
            remaining: figure ? round2(figure.remaining) : null
        };
    });

    // ---------- per program ----------
    const programRows = programs.map(program => {
        const id = toId(program._id);
        const own = deliveries.filter(delivery => toId(delivery.program?._id || delivery.program) === id);
        const ownIds = new Set(own.map(delivery => toId(delivery._id)));
        const people = new Set(links.filter(link => ownIds.has(toId(link.serviceDelivery._id))).map(link => link.beneficiaryId));
        const enrolled = enrollments.filter(item => toId(item.program) === id);
        const figure = figures.programs?.[id];
        const funding = donations.filter(donation => toId(donation.program) === id)
            .reduce((totals, donation) => addTo(totals, donation.currency, donation.amount), {});
        const ownProjects = projectRows.filter(row => row.programId === id);
        return {
            id,
            code: program.programCode,
            name: program.name,
            status: program.status,
            projects: ownProjects.length,
            target: toNumber(program.targetBeneficiaries) || null,
            enrolled: enrolled.length,
            active: enrolled.filter(item => item.status === "Active").length,
            reached: people.size,
            deliveries: own.length,
            value: round2(own.reduce((sum, delivery) => sum + toNumber(delivery.totalAmount), 0)),
            funding: formatTotals(funding),
            approved: figure ? round2(figure.approvedAmount) : null,
            budgetCurrency: figure?.currency || "",
            spentInPeriod: round2(ownProjects.reduce((sum, row) => sum + row.spentInPeriod, 0)),
            spentToDate: figure ? round2(figure.spent) : null
        };
    });

    // ---------- totals ----------
    const allPeople = new Set(links.map(link => link.beneficiaryId));
    const fundingTotals = donations.reduce((totals, donation) => addTo(totals, donation.currency, donation.amount), {});
    const approvedTotals = programRows.reduce((totals, row) => (row.approved ? addTo(totals, row.budgetCurrency, row.approved) : totals), {});
    const spentTotals = projectRows.reduce((totals, row) => (row.spentInPeriod ? addTo(totals, row.budgetCurrency, row.spentInPeriod) : totals), {});

    const moneyColumns = (rows) =>
        money
            ? [
                column("approved", "Approved budget", "money"),
                column("budgetCurrency", "Currency"),
                column("spentInPeriod", "Spent in period", "money"),
                column("spentToDate", "Spent to date", "money"),
                ...(rows === "projects" ? [column("remaining", "Remaining", "money")] : [])
            ]
            : [];

    return buildReport({
        key: "programs",
        title: "Programs & projects",
        description: "Each program and project: people enrolled and reached, what was delivered, money received" + (money ? ", budget and spending." : "."),
        period,
        summary: [
            summaryItem("Programs", programs.length, "number", { note: `${programs.filter(program => program.status === "Active").length} active` }),
            summaryItem("Projects", projects.length, "number", { note: `${projects.filter(project => project.status === "Active").length} active` }),
            summaryItem("People enrolled", enrollments.length),
            summaryItem("People reached by services", allPeople.size),
            summaryItem("Value delivered", round2(deliveries.reduce((sum, delivery) => sum + toNumber(delivery.totalAmount), 0)), "money", { currency: "ETB" }),
            summaryItem("Funding received", formatTotals(fundingTotals), "text"),
            ...(money
                ? [
                    summaryItem("Approved budgets", formatTotals(approvedTotals), "text"),
                    summaryItem("Spent in the period", formatTotals(spentTotals), "text")
                ]
                : [])
        ],
        sections: [
            section("programs", "Programs", [
                column("code", "Code"),
                column("name", "Program"),
                column("status", "Status"),
                column("projects", "Projects", "number"),
                column("target", "Target people", "number"),
                column("enrolled", "Beneficiaries enrolled", "number"),
                column("reached", "Beneficiaries reached by services", "number"),
                column("value", "Value delivered", "money", { currency: "ETB" }),
                column("funding", "Funding received"),
                ...moneyColumns("programs")
            ], programRows, {
                link: { kind: "program", idKey: "id" },
                chart: { type: "bar", x: "name", series: ["enrolled", "reached"], yLabel: "Beneficiaries" }
            })
        ],
        details: {
            title: "Projects",
            link: { kind: "project", idKey: "id" },
            columns: [
                column("code", "Code"),
                column("name", "Project"),
                column("status", "Status"),
                column("start", "Start", "date"),
                column("end", "End", "date"),
                column("donor", "Donor"),
                column("activities", "Activities", "number"),
                column("deliveries", "Deliveries", "number"),
                column("reached", "People reached", "number"),
                column("value", "Value delivered", "money", { currency: "ETB" }),
                ...moneyColumns("projects")
            ],
            rows: projectRows
        }
    });

};


module.exports = {
    key: "programs",
    title: "Programs & projects",
    description: "Each program and project: people reached, what was delivered, funding, budget and spending.",
    filters: ["program", "status"],
    detail: "program",
    generate
};
