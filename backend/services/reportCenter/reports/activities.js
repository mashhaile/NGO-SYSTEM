// =====================================================
// ACTIVITIES & TRAINING REPORT
// =====================================================
//
// Every activity of the period, in two kinds:
//
//   Trainings     trainings, workshops, seminars and
//                 conferences, and any activity that held
//                 attendance sessions: people trained
//                 against the target, who completed every
//                 session, women trained, attendance rate
//
//   Other         distributions, field visits, meetings,
//   activities    campaigns …: what they delivered and to
//                 whom (beneficiaries, institutions,
//                 households and groups) and its value
//
// A participant is a beneficiary, a staff member or an
// external person, counted once however many sessions
// they attended. Replaces the Activity, Activity Run,
// Training, Attendance and Attendance Summary reports.
//
// Filters: program, project, status (of the activity)
//
// =====================================================

const Activity = require("../../../models/Activity");
const ActivityRun = require("../../../models/ActivityRun");
const Attendance = require("../../../models/Attendance");
const AttendanceRecord = require("../../../models/AttendanceRecord");

const {
    scope, objectId, toId, round2, percent, groupRows, locationText,
    summaryItem, column, section, buildReport, projectIn
} = require("../core");

const { inPeriod, monthKey, monthName } = require("../period");
const { loadDeliveries, loadServedLinks, recipientsOf, moneyText } = require("../data");


const LEARNING_TYPES = ["Training", "Workshop", "Seminar", "Conference"];
const ATTENDED = ["Present", "Late"];
const STATUS_ORDER = ["Present", "Late", "Excused", "Absent"];
const AGE_ORDER = ["Child", "Youth", "Adult", "Elderly", "Unknown"];

// the same person in every session
const participantKey = (record) =>
    record.beneficiary ? `b:${toId(record.beneficiary)}`
        : record.staff ? `s:${toId(record.staff)}`
            : record.externalParticipant?.name ? `x:${String(record.externalParticipant.name).trim().toLowerCase()}`
                : `r:${toId(record._id)}`;

const genderOf = (record) => record.gender || record.externalParticipant?.gender || "";

const valueOf = (deliveries) => round2(deliveries.reduce((sum, delivery) => sum + Number(delivery.totalAmount || 0), 0));


const generate = async (query, context, period) => {

    const { organizationId } = context;

    // ---------- activities in scope ----------
    const activityFilter = {};
    if (objectId(query.project)) activityFilter.project = projectIn(query);
    if (query.status) activityFilter.status = query.status;

    let activities =
        await Activity.find(scope(organizationId, activityFilter))
            .select("activityCode name activityType participantSource activityDate status targetParticipants project facilitator region zone woreda")
            .populate({ path: "project", select: "projectCode name program", populate: { path: "program", select: "name" } })
            .lean();

    if (objectId(query.program)) {
        activities = activities.filter(activity => toId(activity.project?.program?._id || activity.project?.program) === String(query.program));
    }

    const activityIds = activities.map(activity => activity._id);
    const activityById = new Map(activities.map(activity => [toId(activity._id), activity]));

    const runs =
        await ActivityRun.find(scope(organizationId, { activity: { $in: activityIds } }))
            .select("runCode name activity startDate endDate status region zone woreda location")
            .lean();

    const runIds = runs.map(run => run._id);

    // ---------- sessions and attendance in the period ----------
    const sessionDate = inPeriod(period);
    const sessions =
        runIds.length
            ? await Attendance.find(scope(organizationId, { activityRun: { $in: runIds }, ...(sessionDate ? { sessionDate } : {}) }))
                .select("activityRun sessionTitle sessionNumber sessionDate")
                .lean()
            : [];

    const records =
        sessions.length
            ? await AttendanceRecord.find(scope(organizationId, { attendance: { $in: sessions.map(item => item._id) } }))
                .select("attendance activityRun participantType gender ageGroup beneficiary staff externalParticipant status")
                .lean()
            : [];

    const sessionById = new Map(sessions.map(item => [toId(item._id), item]));

    // ---------- what activities delivered in the period ----------
    const deliveries = activityIds.length ? await loadDeliveries(organizationId, period, { activity: { $in: activityIds } }) : [];
    const links = await loadServedLinks(organizationId, deliveries);

    const peopleOf = (deliveryList) => {
        const ids = new Set(deliveryList.map(delivery => toId(delivery._id)));
        return new Set(links.filter(link => ids.has(toId(link.serviceDelivery._id))).map(link => link.beneficiaryId)).size;
    };

    // ---------- which activities and runs belong to the period ----------
    const inside = (date) => {
        if (!date) return false;
        const time = new Date(date).getTime();
        return (!period.start || time >= period.start.getTime()) && (!period.end || time < period.end.getTime());
    };

    const runOverlaps = (run) => {
        if (!period.start && !period.end) return true;
        const start = run.startDate ? new Date(run.startDate) : null;
        const end = run.endDate ? new Date(run.endDate) : start;
        if (!start) return false;
        return (!period.end || start < period.end) && (!period.start || (end || start) >= period.start);
    };

    const sessionRuns = new Set(sessions.map(item => toId(item.activityRun)));
    const deliveryRuns = new Set(deliveries.map(item => toId(item.activityRun)).filter(Boolean));
    const periodRuns = runs.filter(run => runOverlaps(run) || sessionRuns.has(toId(run._id)) || deliveryRuns.has(toId(run._id)));

    const periodActivityIds = new Set([
        ...periodRuns.map(run => toId(run.activity)),
        ...deliveries.map(delivery => toId(delivery.activity?._id || delivery.activity)),
        ...activities.filter(activity => inside(activity.activityDate)).map(activity => toId(activity._id))
    ]);

    const periodActivities = activities.filter(activity => periodActivityIds.has(toId(activity._id)));

    // a training: a learning type, or it held sessions
    const runsOf = (activityId) => new Set(runs.filter(run => toId(run.activity) === activityId).map(run => toId(run._id)));
    const sessionsOf = (activityId) => { const own = runsOf(activityId); return sessions.filter(item => own.has(toId(item.activityRun))); };
    const isTraining = (activity) => LEARNING_TYPES.includes(activity.activityType) || sessionsOf(toId(activity._id)).length > 0;

    const trainings = periodActivities.filter(isTraining);
    const others = periodActivities.filter(activity => !isTraining(activity));

    // ---------- training: participants and completion ----------
    const attendedRecords = records.filter(record => ATTENDED.includes(record.status));

    const runSessions = new Map();
    for (const item of sessions) runSessions.set(toId(item.activityRun), (runSessions.get(toId(item.activityRun)) || 0) + 1);

    // sessions each person attended, per run
    const attendedCount = new Map();
    for (const record of attendedRecords) {
        const key = `${toId(record.activityRun)}|${participantKey(record)}`;
        attendedCount.set(key, (attendedCount.get(key) || 0) + 1);
    }

    // who attended every session of a run
    const completedIn = (runId) =>
        new Set([...attendedCount.entries()]
            .filter(([key, count]) => key.startsWith(`${runId}|`) && count >= (runSessions.get(runId) || Infinity))
            .map(([key]) => key.slice(key.indexOf("|") + 1)));

    const trainees = new Map();
    for (const record of attendedRecords) if (!trainees.has(participantKey(record))) trainees.set(participantKey(record), record);
    const traineeRows = [...trainees.values()];

    const completedAll = new Set();
    for (const runId of runSessions.keys()) for (const person of completedIn(runId)) completedAll.add(person);

    const women = traineeRows.filter(record => /^female$/i.test(genderOf(record))).length;
    const trainingTarget = trainings.reduce((sum, activity) => sum + (activity.targetParticipants || 0), 0);

    const trainingRows = trainings.map(activity => {
        const id = toId(activity._id);
        const ownRunIds = new Set(periodRuns.filter(run => toId(run.activity) === id).map(run => toId(run._id)));
        const ownRecords = records.filter(record => ownRunIds.has(toId(record.activityRun)));
        const ownAttended = ownRecords.filter(record => ATTENDED.includes(record.status));
        const people = new Set(ownAttended.map(participantKey));
        const completed = new Set();
        for (const runId of ownRunIds) for (const person of completedIn(runId)) completed.add(person);
        return {
            id,
            code: activity.activityCode,
            name: activity.name,
            type: activity.activityType,
            program: activity.project?.program?.name || "",
            runs: ownRunIds.size,
            sessions: sessions.filter(item => ownRunIds.has(toId(item.activityRun))).length,
            target: activity.targetParticipants || null,
            trained: people.size,
            ofTarget: activity.targetParticipants ? percent(people.size, activity.targetParticipants) : null,
            completed: completed.size,
            women: [...people].filter(key => /^female$/i.test(genderOf(trainees.get(key)))).length,
            rate: ownRecords.length ? percent(ownAttended.length, ownRecords.length) : null,
            status: activity.status
        };
    });

    // ---------- other activities: what they delivered ----------
    const deliveriesOf = (activityId) => deliveries.filter(delivery => toId(delivery.activity?._id || delivery.activity) === activityId);

    const otherRows = others.map(activity => {
        const id = toId(activity._id);
        const own = deliveriesOf(id);
        const { institutions, groups } = recipientsOf(own);
        return {
            id,
            code: activity.activityCode,
            name: activity.name,
            type: activity.activityType,
            program: activity.project?.program?.name || "",
            runs: periodRuns.filter(run => toId(run.activity) === id).length,
            deliveries: own.length,
            people: peopleOf(own),
            institutions: institutions.count,
            groups: groups.count,
            value: valueOf(own),
            status: activity.status
        };
    });

    // ---------- by type ----------
    const typeRows = groupRows(periodActivities, activity => activity.activityType, {
        activities: () => 1,
        runs: activity => periodRuns.filter(run => toId(run.activity) === toId(activity._id)).length,
        sessions: activity => sessionsOf(toId(activity._id)).length,
        deliveries: activity => deliveriesOf(toId(activity._id)).length,
        value: activity => valueOf(deliveriesOf(toId(activity._id)))
    });

    // ---------- by month ----------
    const monthRows = (() => {
        const map = new Map();
        const entry = (key) => {
            if (!map.has(key)) map.set(key, { key, sessions: 0, trained: new Set(), records: 0, present: 0, deliveries: 0, value: 0 });
            return map.get(key);
        };
        for (const item of sessions) entry(monthKey(item.sessionDate)).sessions += 1;
        for (const record of records) {
            const date = sessionById.get(toId(record.attendance))?.sessionDate;
            if (!date) continue;
            const row = entry(monthKey(date));
            row.records += 1;
            if (ATTENDED.includes(record.status)) { row.present += 1; row.trained.add(participantKey(record)); }
        }
        for (const delivery of deliveries) {
            const row = entry(monthKey(delivery.deliveryDate));
            row.deliveries += 1;
            row.value += Number(delivery.totalAmount || 0);
        }
        return [...map.values()].sort((a, b) => a.key.localeCompare(b.key)).map(row => ({
            label: monthName(row.key),
            sessions: row.sessions,
            trained: row.trained.size,
            rate: row.records ? percent(row.present, row.records) : null,
            deliveries: row.deliveries,
            value: round2(row.value)
        }));
    })();

    // ---------- runs (details) ----------
    const runRows = periodRuns.map(run => {
        const runId = toId(run._id);
        const activity = activityById.get(toId(run.activity));
        const ownRecords = records.filter(record => toId(record.activityRun) === runId);
        const attended = ownRecords.filter(record => ATTENDED.includes(record.status));
        const own = deliveries.filter(delivery => toId(delivery.activityRun) === runId);
        const { institutions, groups } = recipientsOf(own);
        return {
            id: runId,
            code: run.runCode,
            activity: activity?.name || "",
            run: run.name,
            kind: activity && isTraining(activity) ? "Training" : "Other",
            type: activity?.activityType || "",
            program: activity?.project?.program?.name || "",
            start: run.startDate,
            end: run.endDate,
            location: locationText(run) || locationText(activity) || "",
            sessions: runSessions.get(runId) || 0,
            participants: new Set(attended.map(participantKey)).size,
            completed: completedIn(runId).size,
            rate: ownRecords.length ? percent(attended.length, ownRecords.length) : null,
            deliveries: own.length,
            people: peopleOf(own),
            institutions: institutions.count,
            groups: groups.count,
            value: valueOf(own),
            status: run.status
        };
    }).sort((a, b) => new Date(a.start) - new Date(b.start));

    const recipients = recipientsOf(deliveries);

    return buildReport({
        key: "activities",
        title: "Activities & training",
        description: "Trainings (people trained, completion, attendance) and other activities (what they delivered and to whom). Each participant is counted once.",
        period,
        summary: [
            summaryItem("Activities", periodActivities.length, "number", { note: `${trainings.length} trainings, ${others.length} other` }),
            summaryItem("Activity runs", periodRuns.length),
            summaryItem("Training sessions held", sessions.length),
            summaryItem("People trained", trainees.size, "number", { note: trainingTarget ? `${percent(trainees.size, trainingTarget)}% of target ${trainingTarget}` : undefined }),
            summaryItem("Completed every session", completedAll.size, "number", { note: `${percent(completedAll.size, trainees.size)}% of people trained` }),
            summaryItem("Women trained", women, "number", { note: `${percent(women, trainees.size)}%` }),
            summaryItem("Attendance rate", percent(attendedRecords.length, records.length), "percent", { note: `${attendedRecords.length} of ${records.length} places filled` }),
            summaryItem("Beneficiaries reached by activity deliveries", peopleOf(deliveries)),
            summaryItem("Institutions reached", recipients.institutions.count, "number", { note: recipients.institutions.count ? moneyText(recipients.institutions.value) : undefined }),
            summaryItem("Households and groups reached", recipients.groups.count, "number", { note: recipients.groups.count ? moneyText(recipients.groups.value) : undefined }),
            summaryItem("Value delivered through activities", valueOf(deliveries), "money", { currency: "ETB" })
        ],
        sections: [
            section("trainings", "Trainings", [
                column("code", "Code"),
                column("name", "Training"),
                column("type", "Type"),
                column("program", "Program"),
                column("runs", "Runs", "number"),
                column("sessions", "Sessions", "number"),
                column("target", "Target", "number"),
                column("trained", "People trained", "number"),
                column("ofTarget", "Of target", "percent"),
                column("completed", "Completed every session", "number"),
                column("women", "Women", "number"),
                column("rate", "Attendance rate", "percent")
            ], trainingRows, {
                link: { kind: "activity", idKey: "id" },
                chart: { type: "bar", x: "name", series: ["target", "trained", "completed"], yLabel: "People" }
            }),
            section("others", "Other activities", [
                column("code", "Code"),
                column("name", "Activity"),
                column("type", "Type"),
                column("program", "Program"),
                column("runs", "Runs", "number"),
                column("deliveries", "Deliveries", "number"),
                column("people", "Beneficiaries reached", "number"),
                column("institutions", "Institutions", "number"),
                column("groups", "Households / groups", "number"),
                column("value", "Value delivered", "money", { currency: "ETB" })
            ], otherRows, { link: { kind: "activity", idKey: "id" } }),
            section("type", "By activity type", [
                column("label", "Type"),
                column("activities", "Activities", "number"),
                column("runs", "Runs", "number"),
                column("sessions", "Training sessions", "number"),
                column("deliveries", "Deliveries", "number"),
                column("value", "Value delivered", "money", { currency: "ETB" })
            ], typeRows),
            section("traineeGender", "People trained, by gender", [
                column("label", "Gender"), column("people", "People", "number")
            ], groupRows(traineeRows, record => genderOf(record), { people: () => 1 }),
            { chart: { type: "pie", x: "label", series: ["people"] } }),
            section("traineeAge", "People trained, by age group", [
                column("label", "Age group"), column("people", "People", "number")
            ], groupRows(traineeRows, record => record.ageGroup, { people: () => 1 }, { order: AGE_ORDER })),
            section("traineeType", "People trained, by type", [
                column("label", "Participant type"), column("people", "People", "number")
            ], groupRows(traineeRows, record => record.participantType, { people: () => 1 }),
            { note: "Beneficiaries, staff, board members, partners, government and community participants." }),
            section("attendance", "Attendance", [
                column("label", "Status"), column("records", "Places", "number")
            ], groupRows(records, record => record.status, { records: () => 1 }, { order: STATUS_ORDER }),
            { chart: { type: "pie", x: "label", series: ["records"] }, note: "One place = one participant in one session." }),
            section("month", "By month", [
                column("label", "Month"),
                column("sessions", "Training sessions", "number"),
                column("trained", "People trained", "number"),
                column("rate", "Attendance rate", "percent"),
                column("deliveries", "Deliveries", "number"),
                column("value", "Value delivered", "money", { currency: "ETB" })
            ], monthRows, { chart: { type: "bar", x: "label", series: ["sessions", "trained", "deliveries"] } })
        ],
        details: {
            title: "Activity runs",
            link: { kind: "activityRun", idKey: "id" },
            columns: [
                column("code", "Run"),
                column("activity", "Activity"),
                column("run", "Name"),
                column("kind", "Kind"),
                column("program", "Program"),
                column("start", "Start", "date"),
                column("end", "End", "date"),
                column("location", "Location"),
                column("sessions", "Sessions", "number"),
                column("participants", "Participants", "number"),
                column("completed", "Completed all", "number"),
                column("rate", "Attendance", "percent"),
                column("deliveries", "Deliveries", "number"),
                column("people", "Beneficiaries reached", "number"),
                column("institutions", "Institutions", "number"),
                column("groups", "Households / groups", "number"),
                column("value", "Value delivered", "money", { currency: "ETB" }),
                column("status", "Status")
            ],
            rows: runRows
        }
    });

};


module.exports = {
    key: "activities",
    title: "Activities & training",
    description: "Trainings: people trained, completion, attendance. Other activities: what they delivered and to whom.",
    filters: ["program", "project", "status"],
    detail: "activityRun",
    generate
};
