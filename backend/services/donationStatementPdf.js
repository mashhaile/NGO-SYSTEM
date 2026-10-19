const Organization =
    require("../models/organization");

const {
    createPdfDocument,
    drawTitle,
    drawSectionTitle,
    drawKeyValueGrid,
    drawTable,
    ensureSpace,
    addPageFooters,
    pdfDate
} = require("./reports/pdf");

const {
    loadDonation,
    traceDonation
} = require("./donationTraceService");



// =====================================================
// DONOR STATEMENT PDF
// =====================================================
//
// "Where did my donation go?" statement for one
// donation, for sending to the donor. Beneficiary names
// are included only when the donor's
// shareBeneficiaryNames setting is on.
//
// =====================================================

const money = (value, currency) =>
    `${currency || "ETB"} ${Number(value || 0).toLocaleString("en-US", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    })}`;


const nameOf = (item) =>
    item
        ? [item.code, item.name].filter(Boolean).join(" - ")
        : "-";


const note = (doc, text) => {

    ensureSpace(doc, 24);

    doc
        .font("Helvetica-Oblique")
        .fontSize(9)
        .fillColor("#555555")
        .text(
            text,
            doc.page.margins.left,
            doc.y,
            {
                width:
                    doc.page.width -
                    doc.page.margins.left -
                    doc.page.margins.right
            }
        )
        .fillColor("#000000");

    doc.moveDown(0.8);

};


const table = (doc, columns, rows, empty) => {

    if (!rows.length) {
        note(doc, empty);
        return;
    }

    drawTable(doc, columns, rows);

    doc.moveDown(0.8);

};


const buildDonationStatementPdf = async (
    donationId,
    organizationId
) => {

    const donation =
        await loadDonation(donationId, organizationId);

    const includeNames =
        Boolean(donation.donor?.shareBeneficiaryNames);

    const [trace, organization] =
        await Promise.all([
            traceDonation(donation, organizationId, { includeNames }),
            Organization.findById(organizationId)
                .select("name")
                .lean()
        ]);

    const currency =
        trace.totals.currency;

    const doc =
        createPdfDocument({
            layout: "portrait"
        });

    const chunks = [];

    doc.on("data", chunk => chunks.push(chunk));

    const finished =
        new Promise((resolve, reject) => {
            doc.on("end", () => resolve(Buffer.concat(chunks)));
            doc.on("error", reject);
        });


    // ---------------- Title ----------------

    drawTitle(
        doc,
        organization?.name || "Donor Statement",
        `DONOR STATEMENT · ${trace.donation.code}`
    );

    doc
        .font("Helvetica-Bold")
        .fontSize(13)
        .text(
            trace.donation.donor?.name || "Donor",
            {
                align: "center"
            }
        );

    doc.moveDown(0.8);


    // ---------------- Summary ----------------

    drawSectionTitle(doc, "SUMMARY");

    drawKeyValueGrid(
        doc,
        [
            { label: "Donation", value: [trace.donation.code, trace.donation.title].filter(Boolean).join(" - ") },
            { label: "Date", value: trace.donation.date ? pdfDate(trace.donation.date) : "-" },
            { label: "Program", value: nameOf(trace.donation.program) },
            { label: "Project", value: nameOf(trace.donation.project) },
            { label: "Restriction", value: trace.donation.fundingRestriction || "-" },
            { label: "Status", value: trace.donation.status },
            { label: "Received", value: money(trace.totals.received, currency) },
            { label: "Used so far", value: `${money(trace.totals.used, currency)} (${trace.totals.percentUsed}%)` },
            { label: "Remaining", value: money(trace.totals.remaining, currency) },
            { label: "Deliveries", value: String(trace.totals.deliveries) },
            { label: "People reached", value: String(trace.totals.beneficiariesReached) },
            { label: "Groups reached", value: String(trace.totals.groupsReached) }
        ],
        {
            columns: 2,
            labelWidth: 90
        }
    );

    doc.moveDown(0.8);

    if (trace.donation.fundingRestriction === "Unrestricted") {
        note(
            doc,
            "This is an unrestricted donation. Only spending recorded against this donation is shown; it also supports the organization's programs more generally."
        );
    }


    // ---------------- What it paid for ----------------

    drawSectionTitle(doc, "WHAT YOUR DONATION PAID FOR");

    table(
        doc,
        [
            { key: "service", label: "Service" },
            { key: "quantity", label: "Quantity", align: "right" },
            { key: "deliveries", label: "Deliveries", align: "right" },
            { key: "amount", label: "Amount", align: "right" }
        ],
        trace.breakdown.byService.map(item => ({
            service: item.service,
            quantity: `${item.quantity} ${item.unit}`.trim(),
            deliveries: String(item.deliveries),
            amount: money(item.amount, currency)
        })),
        "No services have been recorded against this donation yet."
    );


    // ---------------- Where ----------------

    drawSectionTitle(doc, "WHERE IT WAS USED");

    table(
        doc,
        [
            { key: "location", label: "Location" },
            { key: "deliveries", label: "Deliveries", align: "right" },
            { key: "amount", label: "Amount", align: "right" }
        ],
        trace.breakdown.byLocation.map(item => ({
            location: item.location,
            deliveries: String(item.deliveries),
            amount: money(item.amount, currency)
        })),
        "No locations recorded yet."
    );


    // ---------------- Who ----------------

    drawSectionTitle(doc, "PEOPLE REACHED");

    const reachRows = [
        ...trace.reach.byGender.map(item => ({ group: "Gender", label: item.label, count: String(item.count) })),
        ...trace.reach.byAge.map(item => ({ group: "Age", label: item.label, count: String(item.count) })),
        ...trace.reach.byRegion.map(item => ({ group: "Region", label: item.label, count: String(item.count) }))
    ];

    table(
        doc,
        [
            { key: "group", label: "By" },
            { key: "label", label: "Group" },
            { key: "count", label: "People", align: "right" }
        ],
        reachRows,
        "No individual beneficiaries recorded yet."
    );

    if (trace.reach.groups.length) {

        ensureSpace(doc, 60);

        doc
            .font("Helvetica-Bold")
            .fontSize(10)
            .text(
                "Groups and institutions reached",
                doc.page.margins.left,
                doc.y
            );

        doc.moveDown(0.4);

        table(
            doc,
            [
                { key: "recipientType", label: "Recipient type" },
                { key: "recipientName", label: "Group / institution" },
                { key: "date", label: "Date" }
            ],
            trace.reach.groups.map(group => ({
                recipientType: group.recipientType,
                recipientName: group.recipientName,
                date: group.date ? pdfDate(group.date) : "-"
            })),
            ""
        );

    }


    // ---------------- Deliveries ----------------

    drawSectionTitle(doc, "DELIVERIES");

    table(
        doc,
        [
            { key: "date", label: "Date" },
            { key: "reference", label: "Reference" },
            { key: "services", label: "Services" },
            { key: "location", label: "Location" },
            { key: "people", label: "People", align: "right" },
            { key: "amount", label: "Amount", align: "right" }
        ],
        trace.deliveries.map(row => ({
            date: row.date ? pdfDate(row.date) : "-",
            reference: row.deliveryNumber,
            services: row.services.map(s => s.service).join(", "),
            location: row.location || "-",
            people:
                row.beneficiaries > 0 || row.recipientType === "Individual"
                    ? String(row.beneficiaries)
                    : row.recipientType === "Group / Community"
                        ? "Group"
                        : row.recipientType,
            amount: money(row.amount, currency)
        })),
        "No deliveries yet."
    );


    // ---------------- Activities ----------------

    if (trace.activities.length) {

        drawSectionTitle(doc, "ACTIVITIES");

        table(
            doc,
            [
                { key: "activity", label: "Activity" },
                { key: "run", label: "Session / batch" },
                { key: "dates", label: "Dates" },
                { key: "attended", label: "Attended", align: "right" }
            ],
            trace.activities.map(item => ({
                activity: item.activity?.name || "-",
                run: item.run?.name || "-",
                dates: item.startDate
                    ? `${pdfDate(item.startDate)}${item.endDate ? ` – ${pdfDate(item.endDate)}` : ""}`
                    : "-",
                attended: String(item.attended)
            })),
            ""
        );

    }


    // ---------------- Names (only if allowed) ----------------

    if (includeNames && trace.beneficiaries?.length) {

        drawSectionTitle(doc, "BENEFICIARIES");

        table(
            doc,
            [
                { key: "number", label: "No." },
                { key: "name", label: "Name" },
                { key: "gender", label: "Gender" },
                { key: "age", label: "Age group" },
                { key: "location", label: "Location" },
                { key: "value", label: "Support value", align: "right" }
            ],
            trace.beneficiaries.map(person => ({
                number: person.number || "-",
                name: person.name,
                gender: person.gender || "-",
                age: person.ageGroup,
                location: [person.kebele && `Kebele ${person.kebele}`, person.location].filter(Boolean).join(", ") || "-",
                value: person.value ? money(person.value, currency) : "-"
            })),
            ""
        );

    }


    note(
        doc,
        `Figures cover delivered services recorded against ${trace.donation.code} up to ${pdfDate(new Date())}. ` +
        (includeNames
            ? "Beneficiary names are shared with this donor's agreement."
            : "Beneficiary identities are not shared; figures are aggregated.")
    );

    addPageFooters(
        doc,
        {
            leftText: `${trace.donation.code} · Donor statement`
        }
    );

    doc.end();

    return {
        buffer: await finished,
        fileName: `${trace.donation.code}-statement.pdf`
    };

};


module.exports = {
    buildDonationStatementPdf
};
