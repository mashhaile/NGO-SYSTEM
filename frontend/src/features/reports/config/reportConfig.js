// =====================================================
// REPORT CONFIGURATION
// =====================================================

export const reportConfig = {

    // =================================================
    // BENEFICIARY
    // =================================================

    beneficiaryReport: {

        key:
            "beneficiaryReport",

        label:
            "Beneficiary Report",

        description:
            "Provides beneficiary demographics, program participation, services received, enterprise relationships, and support value.",

        category:
            "Beneficiary",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true,

            enterprise:
                true

        }

    },


    beneficiaryHistoryReport: {

        key:
            "beneficiaryHistoryReport",

        label:
            "Beneficiary History Report",

        description:
            "Provides beneficiary enrollment history, service delivery history, programs, projects, activities, service types, and support value.",

        category:
            "Beneficiary",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true,

            enterprise:
                true

        }

    },


    // =================================================
    // PROGRAM
    // =================================================

    programReport: {

        key:
            "programReport",

        label:
            "Program Report",

        description:
            "Provides program information, projects, activities, beneficiaries, enrollments, services, and implementation performance.",

        category:
            "Program",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true

        }

    },


    programImpactReport: {

        key:
            "programImpactReport",

        label:
            "Program Impact Report",

        description:
            "Provides program-level impact indicators, beneficiary reach, participation, service delivery, and outcome information.",

        category:
            "Program",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true

        }

    },


    // =================================================
    // PROJECT
    // =================================================

    projectReport: {

        key:
            "projectReport",

        label:
            "Project Report",

        description:
            "Provides project implementation information, activities, activity runs, beneficiaries, services, and performance.",

        category:
            "Project",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true

        }

    },


    // =================================================
    // ACTIVITY
    // =================================================

    activityReport: {

        key:
            "activityReport",

        label:
            "Activity Report",

        description:
            "Provides activity information, implementation status, activity runs, participants, attendance, and related services.",

        category:
            "Activity",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true,

            location:
                true

        }

    },


    // =================================================
    // ACTIVITY RUN
    // =================================================

    activityRunReport: {

        key:
            "activityRunReport",

        label:
            "Activity Run Report",

        description:
            "Provides activity run implementation details, participant information, attendance, location, status, and related records.",

        category:
            "Activity",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true,

            location:
                true

        }

    },


    // =================================================
    // TRAINING
    // =================================================

    trainingReport: {

        key:
            "trainingReport",

        label:
            "Training Report",

        description:
            "Provides training activities, participants, attendance, training sessions, and implementation information.",

        category:
            "Training",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true

        }

    },


    // =================================================
    // ENROLLMENT
    // =================================================

    enrollmentReport: {

        key:
            "enrollmentReport",

        label:
            "Enrollment Report",

        description:
            "Provides beneficiary enrollment information, program participation, enrollment status, completion, exits, and duration.",

        category:
            "Enrollment",

        filters: {

            date:
                true,

            program:
                true

        }

    },


    // =================================================
    // ATTENDANCE
    // =================================================

    attendanceReport: {

        key:
            "attendanceReport",

        label:
            "Attendance Report",

        description:
            "Provides detailed attendance records by participant, activity, activity run, gender, participant type, status, and location.",

        category:
            "Attendance",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true,

            location:
                true

        }

    },


    attendanceSummaryReport: {

        key:
            "attendanceSummaryReport",

        label:
            "Attendance Summary Report",

        description:
            "Provides summarized attendance information by activity, participant type, gender, status, and reporting period.",

        category:
            "Attendance",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true

        }

    },


    // =================================================
    // SERVICE DELIVERY
    // =================================================

    serviceDeliveryReport: {

        key:
            "serviceDeliveryReport",

        label:
            "Service Delivery Report",

        description:
            "Provides service delivery records, beneficiaries, programs, projects, activities, service types, quantities, costs, and delivery status.",

        category:
            "Service Delivery",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true,

            location:
                true

        }

    },


    monthlyServiceReport: {

        key:
            "monthlyServiceReport",

        label:
            "Monthly Service Report",

        description:
            "Provides monthly service delivery trends, beneficiary reach, service types, quantities, and support value.",

        category:
            "Service Delivery",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true

        }

    },


    // =================================================
    // ENTERPRISE
    // =================================================

    enterpriseReport: {

        key:
            "enterpriseReport",

        label:
            "Enterprise Report",

        description:
            "Provides enterprise information, ownership, business sector, enterprise members, beneficiaries, and status.",

        category:
            "Enterprise",

        filters: {

            date:
                true,

            enterprise:
                true

        }

    },


    // Was missing here, so the list showed its code name
    enterpriseParticipationReport: {

        key:
            "enterpriseParticipationReport",

        label:
            "Enterprise Participation Report",

        description:
            "Enterprise participation and engagement report.",

        category:
            "Enterprise",

        filters: {

            date:
                true,

            enterprise:
                true

        }

    },


    enterpriseImpactReport: {

        key:
            "enterpriseImpactReport",

        label:
            "Enterprise Impact Report",

        description:
            "Provides enterprise participation, beneficiary membership, enterprise performance, and impact information.",

        category:
            "Enterprise",

        filters: {

            date:
                true,

            enterprise:
                true

        }

    },


    // =================================================
    // DONOR
    // =================================================

    donorReport: {

        key:
            "donorReport",

        label:
            "Donor Report",

        description:
            "Provides donor information, donor types, contributions, funding sources, donation status, and supported programs.",

        category:
            "Donor",

        filters: {

            date:
                true,

            program:
                true

        }

    },


    donorImpactReport: {

        key:
            "donorImpactReport",

        label:
            "Donor Impact Report",

        description:
            "Provides donor contribution information, supported programs, beneficiaries reached, services delivered, and impact indicators.",

        category:
            "Donor",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true

        }

    },


    // =================================================
    // FINANCIAL
    // =================================================

    financialReport: {

        key:
            "financialReport",

        label:
            "Financial Report",

        description:
            "Provides financial information across donations, funding sources, programs, projects, activities, and reporting periods.",

        category:
            "Financial",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true

        }

    },


    // Budgets vs approved expenses for one fiscal year
    // (the year chosen in the period filter)

    budgetVsActualReport: {

        key:
            "budgetVsActualReport",

        label:
            "Budget vs Actual",

        description:
            "Approved project budgets for one fiscal year against approved expenses: by project and line, burn rate (% spent vs % of the year passed) and over-budget lines. Uses this year, or the year of the start date if you pick one.",

        category:
            "Financial",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true

        }

    },


    donorSpendingReport: {

        key:
            "donorSpendingReport",

        label:
            "Spending by Donor",

        description:
            "Approved expenses by donor and donation, and spending not linked to any donation.",

        category:
            "Financial",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true

        }

    },


    // =================================================
    // DASHBOARD
    // =================================================

    dashboardReport: {

        key:
            "dashboardReport",

        label:
            "Dashboard Report",

        description:
            "Provides organization-wide program, beneficiary, service delivery, attendance, enterprise, donor, and financial indicators.",

        category:
            "Dashboard",

        filters: {

            date:
                true,

            program:
                true,

            project:
                true,

            activity:
                true,

            activityRun:
                true,

            enterprise:
                true

        }

    }

};


// =====================================================
// GET REPORT CONFIGURATION
// =====================================================

export const getReportConfig =
    (
        reportName
    ) => {

        return (
            reportConfig[reportName] ||
            null
        );

    };


// =====================================================
// GET REPORT LABEL
// =====================================================

export const getReportLabel =
    (
        reportName
    ) => {

        return (
            reportConfig[reportName]?.label ||
            reportName
        );

    };


// =====================================================
// GET ALL REPORT CONFIGURATIONS
// =====================================================

export const getAllReportConfigs =
    () => {

        return Object.values(
            reportConfig
        );

    };


// =====================================================
// GET REPORTS BY CATEGORY
// =====================================================

export const getReportsByCategory =
    (
        category
    ) => {

        return Object.values(
            reportConfig
        ).filter(
            (
                report
            ) =>
                report.category ===
                category
        );

    };