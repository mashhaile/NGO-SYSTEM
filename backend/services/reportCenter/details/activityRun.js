// =====================================================
// ACTIVITY RUN (detail report)
// =====================================================
//
// One run of an activity (a training given to one group):
// each session, the attendance sheet (every participant
// and the sessions they attended), and what was delivered
// during the run.
//
// =====================================================

const ActivityRun = require("../../../models/ActivityRun");
const Attendance = require("../../../models/Attendance");
const AttendanceRecord = require("../../../models/AttendanceRecord");

const {
    scope, objectId, toId, round2, percent, fullName, locationText,
    summaryItem, column, section, buildReport, notFound
} = require("../core");

const { loadDeliveries, loadServedLinks } = require("../data");


const ATTENDED = ["Present", "Late"];


const generate = async (id, query, context, period) => {

    const { organizationId } = context;

    const run =
        objectId(id) &&
        await ActivityRun.findOne(scope(organizationId, { _id: objectId(id) }))
            .populate({ path: "activity", select: "activityCode name activityType facilitator targetParticipants" })
            .populate("project", "projectCode name")
            .populate("program", "programCode name")
            .populate("trainer", "firstName lastName name")
            .lean();

    if (!run) throw notFound("Activity run");

    const sessions =
        await Attendance.find(scope(organizationId, { activityRun: run._id }))
            .sort({ sessionDate: 1, sessionNumber: 1 })
            .lean();

    const records =
        sessions.length
            ? await AttendanceRecord.find(scope(organizationId, { attendance: { $in: sessions.map(item => item._id) } }))
                .populate("beneficiary", "beneficiaryNumber firstName middleName lastName")
                .populate("staff", "firstName lastName name")
                .lean()
            : [];

    // ---------- the attendance sheet ----------
    const sheet = new Map();
    for (const record of records) {
        const key =
            record.beneficiary ? `b:${toId(record.beneficiary._id || record.beneficiary)}`
                : record.staff ? `s:${toId(record.staff._id || record.staff)}`
                    : `x:${String(record.externalParticipant?.name || record._id).trim().toLowerCase()}`;
        const row = sheet.get(key) || {
            id: record.beneficiary ? toId(record.beneficiary._id) : "",
            number: record.beneficiary?.beneficiaryNumber || "",
            name: record.beneficiary ? fullName(record.beneficiary)
                : record.staff ? (record.staff.name || fullName(record.staff))
                    : record.externalParticipant?.name || "Unnamed",
            type: record.participantType || "",
            gender: record.gender || record.externalParticipant?.gender || "",
            attended: 0,
            absent: 0,
            marked: 0
        };
        row.marked += 1;
        if (ATTENDED.includes(record.status)) row.attended += 1;
        if (record.status === "Absent") row.absent += 1;
        sheet.set(key, row);
    }

    const sheetRows =
        [...sheet.values()]
            .map(row => ({ ...row, sessions: `${row.attended} of ${sessions.length}`, rate: percent(row.attended, sessions.length) }))
            .sort((a, b) => b.attended - a.attended || a.name.localeCompare(b.name));

    // ---------- what was delivered during the run ----------
    const deliveries = await loadDeliveries(organizationId, { start: null, end: null }, { activityRun: run._id });
    const links = await loadServedLinks(organizationId, deliveries);

    const attended = records.filter(record => ATTENDED.includes(record.status));

    return buildReport({
        key: "activityRun",
        title: `${run.activity?.name ? `${run.activity.name}: ` : ""}${run.name}`,
        description: `Activity run ${run.runCode || ""}: sessions, attendance sheet and deliveries.`,
        period: { label: "Whole run", type: "all" },
        record: {
            fields: [
                { label: "Run", value: run.runCode },
                { label: "Activity", value: run.activity ? `${run.activity.activityCode || ""} ${run.activity.name}`.trim() : "" },
                { label: "Type", value: run.activity?.activityType },
                { label: "Program", value: run.program?.name },
                { label: "Project", value: run.project?.name },
                { label: "Start", value: run.startDate, format: "date" },
                { label: "End", value: run.endDate, format: "date" },
                { label: "Location", value: [run.location, locationText(run)].filter(Boolean).join(", ") },
                { label: "Trainer / facilitator", value: run.trainer ? (run.trainer.name || fullName(run.trainer)) : run.activity?.facilitator },
                { label: "Target group", value: run.targetGroup },
                { label: "Status", value: run.status }
            ]
        },
        summary: [
            summaryItem("Sessions", sessions.length),
            summaryItem("Participants", sheet.size, "number", { note: run.activity?.targetParticipants ? `target ${run.activity.targetParticipants}` : undefined }),
            summaryItem("Attendance rate", percent(attended.length, records.length), "percent"),
            summaryItem("Completed every session", sheetRows.filter(row => sessions.length && row.attended === sessions.length).length),
            summaryItem("Value delivered", round2(deliveries.reduce((sum, delivery) => sum + Number(delivery.totalAmount || 0), 0)), "money", { currency: "ETB" })
        ],
        sections: [
            section("sessions", "Sessions", [
                column("date", "Date", "date"),
                column("number", "No.", "number"),
                column("title", "Session"),
                column("present", "Present", "number"),
                column("late", "Late", "number"),
                column("excused", "Excused", "number"),
                column("absent", "Absent", "number")
            ], sessions.map(item => {
                const own = records.filter(record => toId(record.attendance) === toId(item._id));
                const count = (status) => own.filter(record => record.status === status).length;
                return { date: item.sessionDate, number: item.sessionNumber, title: item.sessionTitle, present: count("Present"), late: count("Late"), excused: count("Excused"), absent: count("Absent") };
            })),
            section("sheet", "Attendance sheet", [
                column("number", "No."),
                column("name", "Participant"),
                column("type", "Type"),
                column("gender", "Gender"),
                column("sessions", "Sessions attended"),
                column("rate", "Attendance", "percent")
            ], sheetRows, { link: { kind: "beneficiary", idKey: "id" } }),
            deliveries.length
                ? section("deliveries", "Delivered during the run", [
                    column("date", "Date", "date"),
                    column("number", "Delivery"),
                    column("people", "People", "number"),
                    column("value", "Value", "money", { currency: "ETB" })
                ], deliveries.map(delivery => ({
                    id: toId(delivery._id),
                    date: delivery.deliveryDate,
                    number: delivery.deliveryNumber,
                    people: links.filter(link => toId(link.serviceDelivery._id) === toId(delivery._id)).length,
                    value: round2(delivery.totalAmount)
                })), { link: { kind: "delivery", idKey: "id" } })
                : null
        ]
    });

};


module.exports = {
    kind: "activityRun",
    title: "Activity run",
    generate
};
