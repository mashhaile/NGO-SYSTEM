// =====================================================
// ACTIVITIES & ATTENDANCE REPORT
// =====================================================
//
// Activities and their runs (a training given in March
// and again in June), the sessions held and who attended.
// Replaces the Activity, Activity Run, Training,
// Attendance and Attendance Summary reports.
//
// A participant is a beneficiary, a staff member or an
// external person; each is counted once however many
// sessions they attended.
//
// Filters: program, project, status (of the activity)
//
// =====================================================

const Activity = require("../../../models/Activity");
const ActivityRun = require("../../../models/ActivityRun");
const Attendance = require("../../../models/Attendance");
const AttendanceRecord = require("../../../models/AttendanceRecord");

const {
    scope, objectId, toId, percent, groupRows, locationText,
    summaryItem, column, section, buildReport
} = require("../core");

const { inPeriod, monthKey, monthName } = require("../period");


const ATTENDED = ["Present", "Late"];
const STATUS_ORDER = ["Present", "Late", "Excused", "Absent"];
const AGE_ORDER = ["Child", "Youth", "Adult", "Elderly", "Unknown"];

// the same person in every session
const participantKey = (record) =>
    record.beneficiary ? `b:${toId(record.beneficiary)}`
        : record.staff ? `s:${toId(record.staff)}`
            : record.externalParticipant?.name ? `x:${String(record.externalParticipant.name).trim().toLowerCase()}`
                : `r:${toId(record._id)}`;


const generate = async (query, context, period) => {

    const { organizationId } = context;

    // ---------- activities ----------
    const activityFilter = {};
    if (objectId(query.project)) activityFilter.project = objectId(query.project);
    if (query.status) activityFilter.status = query.status;

    let activities =
        await Activity.find(scope(organizationId, activityFilter))
            .select("activityCode name activityType participantSource activityDate status targetParticipants project region zone woreda")
            .populate({ path: "project", select: "projectCode name program", populate: { path: "program", select: "name" } })
            .lean();

    if (objectId(query.program)) {
        activities = activities.filter(activity => toId(activity.project?.program?._id || activity.project?.program) === String(query.program));
    }

    const activityIds = activities.map(activity => activity._id);
    const activityById = new Map(activities.map(activity => [toId(activity._id), activity]));

    // ---------- sessions in the period, and their runs ----------
    const sessionDate = inPeriod(period);
    const sessions =
        await Attendance.find(scope(organizationId, sessionDate ? { sessionDate } : {}))
            .select("activityRun sessionTitle sessionNumber sessionDate")
            .lean();

    const runs =
        await ActivityRun.find(scope(organizationId, { activity: { $in: activityIds } }))
            .select("runCode name activity startDate endDate status region zone woreda targetGroup")
            .lean();

    const runIds = new Set(runs.map(run => toId(run._id)));
    const periodSessions = sessions.filter(item => runIds.has(toId(item.activityRun)));

    // a run is in the period if it overlaps it or held a session in it
    const overlaps = (run) => {
        const start = run.startDate ? new Date(run.startDate) : null;
        const end = run.endDate ? new Date(run.endDate) : start;
        if (!period.start && !period.end) return true;
        if (!start) return false;
        return (!period.end || start < period.end) && (!period.start || (end || start) >= period.start);
    };
    const sessionRuns = new Set(periodSessions.map(item => toId(item.activityRun)));
    const periodRuns = runs.filter(run => overlaps(run) || sessionRuns.has(toId(run._id)));

    const records =
        periodSessions.length
            ? await AttendanceRecord.find(scope(organizationId, { attendance: { $in: periodSessions.map(item => item._id) } }))
                .select("attendance activityRun participantType gender ageGroup disabilityStatus beneficiary staff externalParticipant status")
                .lean()
            : [];

    const sessionById = new Map(periodSessions.map(item => [toId(item._id), item]));

    // ---------- counts ----------
    const attendedRecords = records.filter(record => ATTENDED.includes(record.status));
    const participants = new Set(attendedRecords.map(participantKey));
    const beneficiaries = new Set(attendedRecords.filter(record => record.beneficiary).map(record => toId(record.beneficiary)));
    const periodActivityIds = new Set([
        ...periodRuns.map(run => toId(run.activity)),
        ...activities.filter(activity => {
            const date = activity.activityDate ? new Date(activity.activityDate) : null;
            return date && (!period.start || date >= period.start) && (!period.end || date < period.end);
        }).map(activity => toId(activity._id))
    ]);
    const periodActivities = activities.filter(activity => periodActivityIds.has(toId(activity._id)));

    // one row per participant (their first record's profile)
    const people = new Map();
    for (const record of attendedRecords) if (!people.has(participantKey(record))) people.set(participantKey(record), record);
    const peopleRows = [...people.values()];

    const runRows = periodRuns.map(run => {
        const activity = activityById.get(toId(run.activity));
        const ownSessions = periodSessions.filter(item => toId(item.activityRun) === toId(run._id));
        const ownRecords = records.filter(record => toId(record.activityRun) === toId(run._id));
        const attended = ownRecords.filter(record => ATTENDED.includes(record.status));
        return {
            id: toId(run._id),
            code: run.runCode,
            activity: activity?.name || "",
            run: run.name,
            type: activity?.activityType || "",
            program: activity?.project?.program?.name || "",
            start: run.startDate,
            end: run.endDate,
            location: locationText(run) || locationText(activity) || "",
            sessions: ownSessions.length,
            participants: new Set(attended.map(participantKey)).size,
            rate: percent(attended.length, ownRecords.length),
            status: run.status
        };
    }).sort((a, b) => new Date(a.start) - new Date(b.start));

    const typeRows = groupRows(periodActivities, activity => activity.activityType, {
        activities: () => 1,
        runs: activity => periodRuns.filter(run => toId(run.activity) === toId(activity._id)).length,
        target: activity => activity.targetParticipants || 0
    });
    for (const row of typeRows) {
        const ids = new Set(periodActivities.filter(activity => (activity.activityType || "Not specified") === row.label).map(activity => toId(activity._id)));
        const ownRuns = new Set(periodRuns.filter(run => ids.has(toId(run.activity))).map(run => toId(run._id)));
        row.sessions = periodSessions.filter(item => ownRuns.has(toId(item.activityRun))).length;
        row.participants = new Set(attendedRecords.filter(record => ownRuns.has(toId(record.activityRun))).map(participantKey)).size;
    }

    const monthRows = (() => {
        const map = new Map();
        for (const item of periodSessions) {
            const key = monthKey(item.sessionDate);
            const row = map.get(key) || { key, sessions: 0, attended: new Set(), records: 0, present: 0 };
            row.sessions += 1;
            map.set(key, row);
        }
        for (const record of records) {
            const key = monthKey(sessionById.get(toId(record.attendance))?.sessionDate);
            const row = map.get(key);
            if (!row) continue;
            row.records += 1;
            if (ATTENDED.includes(record.status)) { row.present += 1; row.attended.add(participantKey(record)); }
        }
        return [...map.values()].sort((a, b) => a.key.localeCompare(b.key)).map(row => ({
            label: monthName(row.key), sessions: row.sessions, participants: row.attended.size, rate: percent(row.present, row.records)
        }));
    })();

    const targetTotal = periodActivities.reduce((sum, activity) => sum + (activity.targetParticipants || 0), 0);

    return buildReport({
        key: "activities",
        title: "Activities & attendance",
        description: "Activities and their runs, the sessions held and who attended. Each participant is counted once.",
        period,
        summary: [
            summaryItem("Activities", periodActivities.length, "number", { note: `${periodActivities.filter(activity => activity.activityType === "Training").length} trainings` }),
            summaryItem("Activity runs", periodRuns.length),
            summaryItem("Sessions held", periodSessions.length),
            summaryItem("Participants", participants.size, "number", { note: targetTotal ? `target ${targetTotal}` : undefined }),
            summaryItem("Beneficiaries among them", beneficiaries.size),
            summaryItem("Attendance rate", percent(attendedRecords.length, records.length), "percent", { note: `${attendedRecords.length} of ${records.length} places filled` })
        ],
        sections: [
            section("type", "By activity type", [
                column("label", "Type"),
                column("activities", "Activities", "number"),
                column("runs", "Runs", "number"),
                column("sessions", "Sessions", "number"),
                column("target", "Target participants", "number"),
                column("participants", "Participants", "number")
            ], typeRows, { chart: { type: "bar", x: "label", series: ["target", "participants"], yLabel: "Participants" } }),
            section("status", "Attendance", [
                column("label", "Status"),
                column("records", "Places", "number")
            ], groupRows(records, record => record.status, { records: () => 1 }, { order: STATUS_ORDER }),
            { chart: { type: "pie", x: "label", series: ["records"] }, note: "One place = one participant in one session." }),
            section("participantType", "Participants by type", [
                column("label", "Type"), column("people", "People", "number")
            ], groupRows(peopleRows, record => record.participantType, { people: () => 1 })),
            section("gender", "Participants by gender", [
                column("label", "Gender"), column("people", "People", "number")
            ], groupRows(peopleRows, record => record.gender || record.externalParticipant?.gender, { people: () => 1 }),
            { chart: { type: "pie", x: "label", series: ["people"] } }),
            section("age", "Participants by age group", [
                column("label", "Age group"), column("people", "People", "number")
            ], groupRows(peopleRows, record => record.ageGroup, { people: () => 1 }, { order: AGE_ORDER })),
            section("month", "By month", [
                column("label", "Month"),
                column("sessions", "Sessions", "number"),
                column("participants", "Participants", "number"),
                column("rate", "Attendance rate", "percent")
            ], monthRows, { chart: { type: "bar", x: "label", series: ["sessions", "participants"] } })
        ],
        details: {
            title: "Activity runs",
            link: { kind: "activityRun", idKey: "id" },
            columns: [
                column("code", "Run"),
                column("activity", "Activity"),
                column("run", "Name"),
                column("type", "Type"),
                column("program", "Program"),
                column("start", "Start", "date"),
                column("end", "End", "date"),
                column("location", "Location"),
                column("sessions", "Sessions", "number"),
                column("participants", "Participants", "number"),
                column("rate", "Attendance rate", "percent"),
                column("status", "Status")
            ],
            rows: runRows
        }
    });

};


module.exports = {
    key: "activities",
    title: "Activities & attendance",
    description: "Activities, trainings and their runs, sessions held, who attended and the attendance rate.",
    filters: ["program", "project", "status"],
    detail: "activityRun",
    generate
};
