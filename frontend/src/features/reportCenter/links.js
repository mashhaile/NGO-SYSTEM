// =====================================================
// WHERE A REPORT ROW OPENS
// =====================================================
//
// A row's link names the kind of record. Records with a
// detail report open it; records that already have a full
// page of their own (a delivery, a donation's trace, a
// budget) open that page.
//
// =====================================================

const DETAIL_REPORTS = [
    "beneficiary",
    "program",
    "project",
    "activityRun",
    "enterprise",
    "donor"
];

const APP_PAGES = {
    delivery: (id) => `/service-deliveries/${id}`,
    donation: (id) => `/donations/${id}/trace`,
    budget: (id) => `/budgets/${id}`,
    activity: (id) => `/activities/${id}`
};

export const linkPath = (link, row) => {

    if (!link) return null;

    const id = row?.[link.idKey || "id"];

    if (!id) return null;

    if (DETAIL_REPORTS.includes(link.kind)) return `/reports/detail/${link.kind}/${id}`;

    return APP_PAGES[link.kind] ? APP_PAGES[link.kind](id) : null;

};
