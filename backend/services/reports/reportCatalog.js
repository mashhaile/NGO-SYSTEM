const reportRegistry = require("./reportRegistry");


// =====================================================
// REPORT CATALOG
// =====================================================
//
// Central list of all available NGO reports.
// The registry contains the actual report generators.
//
// Supported reporting periods:
// - Monthly
// - Quarterly
// - Six Monthly / Semi Annual
// - Annual
// - Custom Date Range
//
// =====================================================


const reportCatalog = {

    // =================================================
    // BENEFICIARY REPORTS
    // =================================================

    beneficiaryReport: {

        name: "Beneficiary Report",

        category: "Beneficiaries",

        description:
            "Beneficiary demographic, status and population report.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.beneficiaryReport

    },


    beneficiaryHistoryReport: {

        name: "Beneficiary History Report",

        category: "Beneficiaries",

        description:
            "Complete beneficiary participation and service history.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.beneficiaryHistoryReport

    },


    // =================================================
    // PROGRAM REPORTS
    // =================================================

    programReport: {

        name: "Program Report",

        category: "Programs",

        description:
            "Program implementation, beneficiaries and activities.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.programReport

    },


    programImpactReport: {

        name: "Program Impact Report",

        category: "Programs",

        description:
            "Program reach, service delivery and beneficiary impact.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.programImpactReport

    },


    // =================================================
    // PROJECT REPORTS
    // =================================================

    projectReport: {

        name: "Project Report",

        category: "Projects",

        description:
            "Project implementation, budget and activity performance.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.projectReport

    },


    // =================================================
    // ACTIVITY REPORTS
    // =================================================

    activityReport: {

        name: "Activity Report",

        category: "Activities",

        description:
            "Activity implementation and participation report.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.activityReport

    },


    activityRunReport: {

        name: "Activity Run Report",

        category: "Activities",

        description:
            "Detailed activity execution/run report.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.activityRunReport

    },


    trainingReport: {

        name: "Training Report",

        category: "Activities",

        description:
            "Training activities, participants and attendance.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.trainingReport

    },


    // =================================================
    // ENROLLMENT REPORTS
    // =================================================

    enrollmentReport: {

        name: "Enrollment Report",

        category: "Enrollments",

        description:
            "Program enrollment, active beneficiaries and exits.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.enrollmentReport

    },


    // =================================================
    // ATTENDANCE REPORTS
    // =================================================

    attendanceReport: {

        name: "Attendance Report",

        category: "Attendance",

        description:
            "Detailed attendance and participant records.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.attendanceReport

    },


    attendanceSummaryReport: {

        name: "Attendance Summary Report",

        category: "Attendance",

        description:
            "Attendance summary by gender, age group, participant type and location.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.attendanceSummaryReport

    },


    // =================================================
    // SERVICE DELIVERY REPORTS
    // =================================================

    serviceDeliveryReport: {

        name: "Service Delivery Report",

        category: "Service Delivery",

        description:
            "Services, goods, quantities, beneficiaries and delivery values.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.serviceDeliveryReport

    },


    monthlyServiceReport: {

        name: "Monthly Service Report",

        category: "Service Delivery",

        description:
            "Monthly service delivery performance and trends.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.monthlyServiceReport

    },


    // =================================================
    // ENTERPRISE REPORTS
    // =================================================

    enterpriseReport: {

        name: "Enterprise Report",

        category: "Enterprise",

        description:
            "Enterprise participation and beneficiary enterprise activities.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.enterpriseReport

    },


    enterpriseParticipationReport: {

        name: "Enterprise Participation Report",

        category: "Enterprise",

        description:
            "Enterprise participation and engagement report.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.enterpriseParticipationReport

    },


    enterpriseImpactReport: {

        name: "Enterprise Impact Report",

        category: "Enterprise",

        description:
            "Enterprise outcomes and impact report.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.enterpriseImpactReport

    },


    // =================================================
    // DONOR REPORTS
    // =================================================

    donorReport: {

        name: "Donor Report",

        category: "Donors",

        description:
            "Donor contributions, projects and funding information.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.donorReport

    },


    donorImpactReport: {

        name: "Donor Impact Report",

        category: "Donors",

        description:
            "Donor-funded activities, beneficiaries and impact.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.donorImpactReport

    },


    // =================================================
    // FINANCIAL REPORTS
    // =================================================

    financialReport: {

        name: "Financial Report",

        category: "Financial",

        description:
            "Financial transactions, funding and expenditure report.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.financialReport

    },


    // =================================================
    // FINANCE (budgets / expenses)
    // =================================================

    budgetVsActualReport: {

        name: "Budget vs Actual",

        category: "Financial",

        description:
            "Approved project budgets for the year against approved expenses: by project and line, burn rate and over-budget lines.",

        periods: [
            "annual"
        ],

        generator:
            reportRegistry.budgetVsActualReport

    },


    donorSpendingReport: {

        name: "Spending by Donor",

        category: "Financial",

        description:
            "Approved expenses by donor and donation, and spending not linked to any donation.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.donorSpendingReport

    },


    // =================================================
    // DASHBOARD
    // =================================================

    dashboardReport: {

        name: "Dashboard Report",

        category: "Dashboard",

        description:
            "Overall NGO performance and key indicators.",

        periods: [
            "monthly",
            "quarterly",
            "sixmonthly",
            "annual",
            "custom"
        ],

        generator:
            reportRegistry.dashboardReport

    }

};


// =====================================================
// EXPORT
// =====================================================

module.exports = reportCatalog;