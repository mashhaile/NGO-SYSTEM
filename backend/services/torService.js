const mongoose =
    require("mongoose");

const TermsOfReference =
    require("../models/TermsOfReference");

const {
    TOR_STATUS
} = require("../models/TermsOfReference");

const Activity =
    require("../models/Activity");

const ActivityRun =
    require("../models/ActivityRun");

const Project =
    require("../models/Project");

const activityService =
    require("./activityService");

const Organization =
    require("../models/organization");

const ApiError =
    require("../utils/apiError");

const generateSequence =
    require("../utils/generateSequence");

const {
    createPdfDocument,
    drawTitle,
    drawSectionTitle,
    drawKeyValueGrid,
    drawTable,
    ensureSpace,
    addPageFooters,
    pdfDate,
    pdfDateTime
} = require("./reports/pdf");



// =====================================================
// CONSTANTS
// =====================================================

const EDITABLE_STATUSES = [
    TOR_STATUS.DRAFT,
    TOR_STATUS.RETURNED
];


// Sections that must be filled before submitting.

const REQUIRED_FOR_SUBMISSION = [
    ["title", "Title"],
    ["background", "Background"],
    ["objectives", "Objectives"],
    ["expectedOutputs", "Expected Outputs"],
    ["startDate", "Start Date"]
];


const USER_FIELDS =
    "name email";


const DETAIL_POPULATE = [
    {
        path: "activity",
        select: "activityCode name activityType"
    },
    {
        path: "activityRun",
        select: "runCode name startDate endDate"
    },
    {
        path: "project",
        select: "projectCode name"
    },
    {
        path: "createdBy",
        select: USER_FIELDS
    },
    {
        path: "submittedBy",
        select: USER_FIELDS
    },
    {
        path: "approvedBy",
        select: USER_FIELDS
    },
    {
        path: "history.by",
        select: USER_FIELDS
    }
];



// =====================================================
// HELPERS
// =====================================================

const toNumber = (value) => {

    const number =
        Number(value);

    return Number.isFinite(number)
        ? number
        : 0;

};


const roundMoney = (value) =>
    Math.round(
        toNumber(value) * 100
    ) / 100;


// Budget line totals and TOR total are always
// calculated here, never trusted from the client.

const normalizeBudget = (lines = []) => {

    const budgetLines =
        (Array.isArray(lines) ? lines : [])
            .map(line => {

                const quantity =
                    toNumber(line.quantity);

                const unitCost =
                    toNumber(line.unitCost);

                return {
                    ...(line._id
                        ? { _id: line._id }
                        : {}),
                    description:
                        String(line.description || "").trim(),
                    unit:
                        String(line.unit || "").trim(),
                    quantity,
                    unitCost,
                    total:
                        roundMoney(quantity * unitCost)
                };

            })
            .filter(line => line.description);

    return {
        budgetLines,
        totalBudget:
            roundMoney(
                budgetLines.reduce(
                    (sum, line) => sum + line.total,
                    0
                )
            )
    };

};


const emptyToNull = (value) =>
    value === "" || value === undefined
        ? null
        : value;


const validateDates = (startDate, endDate) => {

    if (
        startDate &&
        endDate &&
        new Date(endDate) < new Date(startDate)
    ) {
        throw new ApiError(
            "End date cannot be before start date.",
            400
        );
    }

};


// Project must belong to the organization. The
// activity is optional (usually created after
// approval); if given it must belong to the same
// project, and the run must belong to the activity.

const resolveLinks = async (
    organizationId,
    projectId,
    activityId,
    activityRunId
) => {

    if (!mongoose.isValidObjectId(projectId)) {
        throw new ApiError(
            "Project is required.",
            400
        );
    }

    const project =
        await Project.findOne({
            _id: projectId,
            organization: organizationId,
            isDeleted: false
        })
            .select("_id")
            .lean();

    if (!project) {
        throw new ApiError(
            "Project not found.",
            404
        );
    }

    if (!activityId) {

        if (activityRunId) {
            throw new ApiError(
                "Select the activity before the activity run.",
                400
            );
        }

        return {
            project: project._id,
            activity: null,
            activityRun: null
        };

    }

    const activity =
        await Activity.findOne({
            _id: activityId,
            organization: organizationId,
            isDeleted: false
        })
            .select("_id project")
            .lean();

    if (!activity) {
        throw new ApiError(
            "Activity not found.",
            404
        );
    }

    if (String(activity.project) !== String(project._id)) {
        throw new ApiError(
            "The activity belongs to a different project than this TOR.",
            400
        );
    }

    let activityRun = null;

    if (activityRunId) {

        activityRun =
            await ActivityRun.findOne({
                _id: activityRunId,
                organization: organizationId,
                activity: activity._id,
                isDeleted: false
            })
                .select("_id")
                .lean();

        if (!activityRun) {
            throw new ApiError(
                "Activity run not found for the selected activity.",
                404
            );
        }

    }

    return {
        project: project._id,
        activity: activity._id,
        activityRun: activityRun?._id || null
    };

};


const assertTorId = (id) => {

    if (!mongoose.isValidObjectId(id)) {
        throw new ApiError(
            "Terms of reference not found.",
            404
        );
    }

};


const findTor = async (
    id,
    organizationId
) => {

    assertTorId(id);

    const tor =
        await TermsOfReference.findOne({
            _id: id,
            organization: organizationId,
            isDeleted: false
        });

    if (!tor) {
        throw new ApiError(
            "Terms of reference not found.",
            404
        );
    }

    return tor;

};


const historyEntry = (
    action,
    status,
    userId,
    comment = ""
) => ({
    action,
    status,
    comment,
    by: userId,
    at: new Date()
});


// Builds the $set for create / update from validated
// input. Only keys present in `data` are included.

const SECTION_FIELDS = [
    "title",
    "activityType",
    "background",
    "objectives",
    "expectedOutputs",
    "methodology",
    "participants",
    "expectedParticipants",
    "facilitators",
    "logistics",
    "reportingRequirements",
    "region",
    "regionCode",
    "zone",
    "zoneCode",
    "woreda",
    "woredaCode",
    "venue",
    "currency"
];


const pickFields = (data) => {

    const fields = {};

    SECTION_FIELDS.forEach(field => {

        if (data[field] !== undefined) {

            fields[field] =
                data[field] === null
                    ? (field === "expectedParticipants" ? 0 : "")
                    : data[field];

        }

    });

    if (data.startDate !== undefined) {
        fields.startDate =
            emptyToNull(data.startDate);
    }

    if (data.endDate !== undefined) {
        fields.endDate =
            emptyToNull(data.endDate);
    }

    if (fields.currency === "") {
        fields.currency = "ETB";
    }

    if (fields.activityType === "") {
        fields.activityType = "Training";
    }

    return fields;

};



// =====================================================
// CREATE
// =====================================================

const createTor = async (
    data,
    organizationId,
    userId
) => {

    validateDates(
        data.startDate,
        data.endDate
    );

    const links =
        await resolveLinks(
            organizationId,
            data.project,
            emptyToNull(data.activity),
            emptyToNull(data.activityRun)
        );

    const torNumber =
        await generateSequence(
            "TermsOfReference",
            "TOR",
            organizationId
        );

    return TermsOfReference.create({

        ...pickFields(data),

        ...links,

        ...normalizeBudget(
            data.budgetLines
        ),

        organization:
            organizationId,

        torNumber,

        status:
            TOR_STATUS.DRAFT,

        history: [
            historyEntry(
                "Created",
                TOR_STATUS.DRAFT,
                userId
            )
        ],

        createdBy:
            userId,

        updatedBy:
            userId

    });

};



// =====================================================
// LIST
// =====================================================

const escapeRegex = (value) =>
    String(value).replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
    );


const getTors = async (
    organizationId,
    query = {}
) => {

    const page =
        Math.max(1, Number(query.page) || 1);

    const limit =
        Math.min(100, Math.max(1, Number(query.limit) || 10));

    const filter = {
        organization: organizationId,
        isDeleted: false
    };

    if (query.status) {
        filter.status = query.status;
    }

    if (query.activity) {
        filter.activity = query.activity;
    }

    if (query.project) {
        filter.project = query.project;
    }

    if (query.search) {

        const pattern = {
            $regex: escapeRegex(query.search),
            $options: "i"
        };

        filter.$or = [
            { torNumber: pattern },
            { title: pattern },
            { venue: pattern }
        ];

    }

    const [data, total] =
        await Promise.all([

            TermsOfReference.find(filter)
                .select(
                    "torNumber title activity activityRun project startDate endDate region zone woreda venue totalBudget currency status submittedAt approvedAt createdAt"
                )
                .populate("activity", "activityCode name")
                .populate("activityRun", "runCode name")
                .populate("project", "projectCode name")
                .sort({ createdAt: -1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean(),

            TermsOfReference.countDocuments(filter)

        ]);

    return {
        data,
        pagination: {
            total,
            page,
            limit,
            pages: Math.ceil(total / limit)
        }
    };

};



// =====================================================
// GET BY ID
// =====================================================

const getTorById = async (
    id,
    organizationId
) => {

    assertTorId(id);

    const tor =
        await TermsOfReference.findOne({
            _id: id,
            organization: organizationId,
            isDeleted: false
        })
            .populate(DETAIL_POPULATE)
            .lean();

    if (!tor) {
        throw new ApiError(
            "Terms of reference not found.",
            404
        );
    }

    return tor;

};



// =====================================================
// UPDATE (Draft / Returned only)
// =====================================================

const updateTor = async (
    id,
    data,
    organizationId,
    userId
) => {

    const tor =
        await findTor(id, organizationId);

    if (!EDITABLE_STATUSES.includes(tor.status)) {
        throw new ApiError(
            `A ${tor.status.toLowerCase()} TOR cannot be edited.`,
            409
        );
    }

    validateDates(
        data.startDate !== undefined ? data.startDate : tor.startDate,
        data.endDate !== undefined ? data.endDate : tor.endDate
    );

    if (
        data.project !== undefined ||
        data.activity !== undefined ||
        data.activityRun !== undefined
    ) {

        Object.assign(
            tor,
            await resolveLinks(
                organizationId,
                data.project || tor.project,
                data.activity !== undefined
                    ? emptyToNull(data.activity)
                    : tor.activity,
                data.activityRun !== undefined
                    ? emptyToNull(data.activityRun)
                    : tor.activityRun
            )
        );

    }

    Object.assign(
        tor,
        pickFields(data)
    );

    if (data.budgetLines !== undefined) {
        Object.assign(
            tor,
            normalizeBudget(data.budgetLines)
        );
    }

    tor.updatedBy = userId;

    tor.history.push(
        historyEntry(
            "Updated",
            tor.status,
            userId
        )
    );

    await tor.save();

    return getTorById(tor._id, organizationId);

};



// =====================================================
// DELETE (Draft / Returned only, soft delete)
// =====================================================

const deleteTor = async (
    id,
    organizationId,
    userId
) => {

    const tor =
        await findTor(id, organizationId);

    if (!EDITABLE_STATUSES.includes(tor.status)) {
        throw new ApiError(
            `A ${tor.status.toLowerCase()} TOR cannot be deleted.`,
            409
        );
    }

    tor.isDeleted = true;
    tor.deletedAt = new Date();
    tor.deletedBy = userId;

    await tor.save();

};



// =====================================================
// WORKFLOW TRANSITIONS
// =====================================================
//
// Each transition is a single conditional update on
// the current status, so two people acting at the same
// time cannot both succeed (e.g. approve + return).
//
// =====================================================

const transition = async ({
    id,
    organizationId,
    userId,
    from,
    to,
    action,
    comment = "",
    set = {},
    verb
}) => {

    assertTorId(id);

    const updated =
        await TermsOfReference.findOneAndUpdate(
            {
                _id: id,
                organization: organizationId,
                isDeleted: false,
                status: {
                    $in: from
                }
            },
            {
                $set: {
                    status: to,
                    updatedBy: userId,
                    ...set
                },
                $push: {
                    history:
                        historyEntry(
                            action,
                            to,
                            userId,
                            comment
                        )
                }
            },
            {
                returnDocument: "after"
            }
        );

    if (!updated) {

        const current =
            await findTor(id, organizationId);

        throw new ApiError(
            `This TOR is ${current.status.toLowerCase()} and cannot be ${verb}.`,
            409
        );

    }

    return getTorById(updated._id, organizationId);

};


const submitTor = async (
    id,
    organizationId,
    userId
) => {

    const tor =
        await findTor(id, organizationId);

    const missing =
        REQUIRED_FOR_SUBMISSION
            .filter(([field]) => {
                const value = tor[field];
                return value === null ||
                    value === undefined ||
                    String(value).trim() === "";
            })
            .map(([, label]) => label);

    if (missing.length) {
        throw new ApiError(
            `Complete these sections before submitting: ${missing.join(", ")}.`,
            400,
            missing.map(label => ({
                field: label,
                message: `${label} is required for submission.`
            }))
        );
    }

    return transition({
        id,
        organizationId,
        userId,
        from: EDITABLE_STATUSES,
        to: TOR_STATUS.SUBMITTED,
        action: "Submitted",
        verb: "submitted",
        set: {
            submittedBy: userId,
            submittedAt: new Date(),
            reviewComment: ""
        }
    });

};


const approveTor = async (
    id,
    organizationId,
    userId,
    comment = ""
) =>
    transition({
        id,
        organizationId,
        userId,
        comment: comment || "",
        from: [TOR_STATUS.SUBMITTED],
        to: TOR_STATUS.APPROVED,
        action: "Approved",
        verb: "approved",
        set: {
            approvedBy: userId,
            approvedAt: new Date()
        }
    });


const returnTor = async (
    id,
    organizationId,
    userId,
    comment
) =>
    transition({
        id,
        organizationId,
        userId,
        comment,
        from: [TOR_STATUS.SUBMITTED],
        to: TOR_STATUS.RETURNED,
        action: "Returned",
        verb: "returned",
        set: {
            reviewComment: comment
        }
    });



// =====================================================
// ACTIVITY FROM APPROVED TOR
// =====================================================
//
// The TOR comes first; once approved, its activity is
// created from it (or an existing one is linked).
//
// =====================================================

const createActivityFromTor = async (
    id,
    organizationId,
    userId
) => {

    const tor =
        await findTor(id, organizationId);

    if (tor.status !== TOR_STATUS.APPROVED) {
        throw new ApiError(
            "Only an approved TOR can create its activity.",
            409
        );
    }

    if (tor.activity) {
        throw new ApiError(
            "This TOR is already linked to an activity.",
            409
        );
    }

    const activity =
        await activityService.createActivity(
            {
                project: tor.project,
                name: tor.title,
                activityType: tor.activityType || "Training",
                participantSource: "Enrolled Beneficiaries",
                targetGroups: [],
                description: tor.objectives,
                activityDate: tor.startDate,
                region: tor.region,
                regionCode: tor.regionCode,
                zone: tor.zone,
                zoneCode: tor.zoneCode,
                woreda: tor.woreda,
                woredaCode: tor.woredaCode,
                location: tor.venue,
                facilitator: tor.facilitators,
                targetParticipants: tor.expectedParticipants || 0,
                status: "Planned",
                remarks: `Created from approved TOR ${tor.torNumber}`
            },
            organizationId,
            userId
        );

    // Link only if nobody linked an activity meanwhile;
    // otherwise remove the activity just created.

    const linked =
        await TermsOfReference.findOneAndUpdate(
            {
                _id: tor._id,
                organization: organizationId,
                isDeleted: false,
                status: TOR_STATUS.APPROVED,
                activity: null
            },
            {
                $set: {
                    activity: activity._id,
                    updatedBy: userId
                },
                $push: {
                    history:
                        historyEntry(
                            "Activity Created",
                            TOR_STATUS.APPROVED,
                            userId,
                            `${activity.activityCode} - ${activity.name}`
                        )
                }
            },
            {
                returnDocument: "after"
            }
        );

    if (!linked) {

        await Activity.deleteOne({
            _id: activity._id
        });

        throw new ApiError(
            "This TOR was linked to another activity in the meantime.",
            409
        );

    }

    return {
        tor:
            await getTorById(tor._id, organizationId),
        activity
    };

};


const linkActivity = async (
    id,
    organizationId,
    userId,
    activityId
) => {

    const tor =
        await findTor(id, organizationId);

    if (
        tor.activity &&
        !EDITABLE_STATUSES.includes(tor.status)
    ) {
        throw new ApiError(
            "This TOR is already linked to an activity.",
            409
        );
    }

    const links =
        await resolveLinks(
            organizationId,
            tor.project,
            activityId,
            null
        );

    const linked =
        await TermsOfReference.findOneAndUpdate(
            {
                _id: tor._id,
                organization: organizationId,
                isDeleted: false,
                activity: tor.activity || null
            },
            {
                $set: {
                    activity: links.activity,
                    activityRun: null,
                    updatedBy: userId
                },
                $push: {
                    history:
                        historyEntry(
                            "Activity Linked",
                            tor.status,
                            userId
                        )
                }
            },
            {
                returnDocument: "after"
            }
        );

    if (!linked) {
        throw new ApiError(
            "This TOR was changed in the meantime. Reload and try again.",
            409
        );
    }

    return getTorById(tor._id, organizationId);

};



// =====================================================
// PDF
// =====================================================

const personName = (user) =>
    user?.name ||
    user?.email ||
    "-";


const codeName = (item, codeKey) =>
    item
        ? [item[codeKey], item.name]
            .filter(Boolean)
            .join(" - ")
        : "-";


// "ETB 1,500.50" in the TOR's own currency.

const formatAmount = (value, currency) =>
    `${currency || "ETB"} ${Number(value || 0).toLocaleString("en-US", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    })}`;


// Numbers only the sections that are actually printed.

const drawParagraphSection = (
    doc,
    title,
    text,
    numbering
) => {

    if (!text || !String(text).trim()) {
        return;
    }

    numbering.count += 1;

    drawSectionTitle(
        doc,
        `${numbering.count}. ${title}`
    );

    ensureSpace(doc, 40);

    doc
        .font("Helvetica")
        .fontSize(10)
        .fillColor("#000000")
        .text(
            String(text).trim(),
            doc.page.margins.left,
            doc.y,
            {
                width:
                    doc.page.width -
                    doc.page.margins.left -
                    doc.page.margins.right,
                align: "justify",
                lineGap: 2
            }
        );

    doc.moveDown(0.8);

};


const drawDraftWatermark = (doc) => {

    const range =
        doc.bufferedPageRange();

    for (
        let index = 0;
        index < range.count;
        index++
    ) {

        doc.switchToPage(range.start + index);

        doc
            .save()
            .rotate(-35, {
                origin: [
                    doc.page.width / 2,
                    doc.page.height / 2
                ]
            })
            .font("Helvetica-Bold")
            .fontSize(48)
            .fillColor("#C62828")
            .opacity(0.12)
            .text(
                "DRAFT – NOT APPROVED",
                0,
                doc.page.height / 2 - 24,
                {
                    width: doc.page.width,
                    align: "center"
                }
            )
            .restore();

    }

};


const buildTorPdf = async (
    id,
    organizationId
) => {

    const [tor, organization] =
        await Promise.all([
            getTorById(id, organizationId),
            Organization.findById(organizationId)
                .select("name")
                .lean()
        ]);

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
        organization?.name || "Terms of Reference",
        `TERMS OF REFERENCE · ${tor.torNumber}`
    );

    doc
        .font("Helvetica-Bold")
        .fontSize(14)
        .text(
            tor.title,
            {
                align: "center"
            }
        );

    doc.moveDown(0.8);


    // ---------------- Overview ----------------

    const location =
        [
            tor.venue,
            tor.woreda,
            tor.zone,
            tor.region
        ]
            .filter(Boolean)
            .join(", ") || "-";

    drawSectionTitle(doc, "OVERVIEW");

    drawKeyValueGrid(
        doc,
        [
            { label: "TOR No.", value: tor.torNumber },
            { label: "Status", value: tor.status },
            { label: "Activity", value: tor.activity ? codeName(tor.activity, "activityCode") : "Not created yet" },
            { label: "Activity Run", value: codeName(tor.activityRun, "runCode") },
            { label: "Project", value: codeName(tor.project, "projectCode") },
            { label: "Participants", value: String(tor.expectedParticipants || "-") },
            { label: "Start Date", value: tor.startDate ? pdfDate(tor.startDate) : "-" },
            { label: "End Date", value: tor.endDate ? pdfDate(tor.endDate) : "-" },
            { label: "Location", value: location },
            { label: "Total Budget", value: formatAmount(tor.totalBudget, tor.currency) }
        ],
        {
            columns: 2,
            labelWidth: 85
        }
    );

    doc.moveDown(0.8);


    // ---------------- Sections ----------------

    const numbering = {
        count: 0
    };

    drawParagraphSection(doc, "BACKGROUND", tor.background, numbering);
    drawParagraphSection(doc, "OBJECTIVES", tor.objectives, numbering);
    drawParagraphSection(doc, "EXPECTED OUTPUTS", tor.expectedOutputs, numbering);
    drawParagraphSection(doc, "METHODOLOGY", tor.methodology, numbering);
    drawParagraphSection(doc, "PARTICIPANTS", tor.participants, numbering);
    drawParagraphSection(doc, "FACILITATORS / RESOURCE PERSONS", tor.facilitators, numbering);
    drawParagraphSection(doc, "LOGISTICS", tor.logistics, numbering);


    // ---------------- Budget ----------------

    if (tor.budgetLines?.length) {

        numbering.count += 1;

        drawSectionTitle(
            doc,
            `${numbering.count}. BUDGET`
        );

        drawTable(
            doc,
            [
                { key: "no", label: "#", align: "center" },
                { key: "description", label: "Description" },
                { key: "unit", label: "Unit" },
                { key: "quantity", label: "Qty", align: "right" },
                { key: "unitCost", label: "Unit Cost", align: "right" },
                { key: "total", label: "Total", align: "right" }
            ],
            [
                ...tor.budgetLines.map((line, index) => ({
                    no: String(index + 1),
                    description: line.description,
                    unit: line.unit || "-",
                    quantity: String(line.quantity),
                    unitCost: formatAmount(line.unitCost, tor.currency),
                    total: formatAmount(line.total, tor.currency)
                })),
                {
                    no: "",
                    description: "TOTAL",
                    unit: "",
                    quantity: "",
                    unitCost: "",
                    total: formatAmount(tor.totalBudget, tor.currency)
                }
            ]
        );

        doc.moveDown(0.8);

    }

    drawParagraphSection(doc, "REPORTING REQUIREMENTS", tor.reportingRequirements, numbering);


    // ---------------- Approval ----------------

    drawSectionTitle(doc, "APPROVAL");

    drawKeyValueGrid(
        doc,
        [
            { label: "Prepared by", value: personName(tor.createdBy) },
            { label: "Prepared on", value: pdfDate(tor.createdAt) },
            { label: "Submitted by", value: tor.submittedBy ? personName(tor.submittedBy) : "-" },
            { label: "Submitted on", value: tor.submittedAt ? pdfDateTime(tor.submittedAt) : "-" },
            { label: "Approved by", value: tor.approvedBy ? personName(tor.approvedBy) : "-" },
            { label: "Approved on", value: tor.approvedAt ? pdfDateTime(tor.approvedAt) : "-" }
        ],
        {
            columns: 2,
            labelWidth: 85
        }
    );


    // ---------------- Finish ----------------

    if (tor.status !== TOR_STATUS.APPROVED) {
        drawDraftWatermark(doc);
    }

    addPageFooters(
        doc,
        {
            leftText:
                `${tor.torNumber} · ${tor.status}`
        }
    );

    doc.end();

    return {
        buffer: await finished,
        fileName: `${tor.torNumber}.pdf`
    };

};



module.exports = {
    TOR_STATUS,
    createTor,
    getTors,
    getTorById,
    updateTor,
    deleteTor,
    submitTor,
    approveTor,
    returnTor,
    createActivityFromTor,
    linkActivity,
    buildTorPdf
};
