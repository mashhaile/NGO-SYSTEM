// =====================================================
// BENEFICIARY PROFILE (detail report)
// =====================================================
//
// One person: who they are, the programs they are in,
// every service they received (their own share), the
// training sessions they attended, and their enterprises.
//
// =====================================================

const Beneficiary = require("../../../models/Beneficiary");
const Enrollment = require("../../../models/enrollment");
const Attendance = require("../../../models/Attendance");
const AttendanceRecord = require("../../../models/AttendanceRecord");
const EnterpriseMember = require("../../../models/EnterpriseMember");

const {
    scope, objectId, toId, round2, fullName, ageOf, lookupText, locationText,
    summaryItem, column, section, buildReport, notFound
} = require("../core");

const { inPeriod } = require("../period");
const { loadDeliveries, loadServedLinks, quantityText, serviceName } = require("../data");


const generate = async (id, query, context, period) => {

    const { organizationId } = context;

    const person =
        objectId(id) &&
        await Beneficiary.findOne(scope(organizationId, { _id: objectId(id) }))
            .populate("gender", "value")
            .populate("educationLevel", "value")
            .populate("occupation", "value")
            .populate("maritalStatus", "value")
            .populate("disabilityType", "value")
            .lean();

    if (!person) throw notFound("Beneficiary");

    // every delivery they are on, in the period
    const ServiceDeliveryBeneficiary = require("../../../models/ServiceDeliveryBeneficiary");
    const ownLinks =
        await ServiceDeliveryBeneficiary.find({ organization: organizationId, beneficiary: person._id })
            .select("serviceDelivery")
            .lean();

    const deliveries =
        ownLinks.length
            ? await loadDeliveries(organizationId, period, { _id: { $in: ownLinks.map(link => link.serviceDelivery) } })
            : [];

    const links =
        (await loadServedLinks(organizationId, deliveries))
            .filter(link => link.beneficiaryId === toId(person._id));

    const enrollments =
        await Enrollment.find(scope(organizationId, { beneficiary: person._id }))
            .populate("program", "programCode name")
            .sort({ enrollmentDate: -1 })
            .lean();

    const sessionDate = inPeriod(period);
    const records =
        await AttendanceRecord.find(scope(organizationId, { beneficiary: person._id }))
            .populate({ path: "attendance", select: "sessionTitle sessionNumber sessionDate", model: Attendance })
            .populate({ path: "activityRun", select: "runCode name activity", populate: { path: "activity", select: "name activityType" } })
            .lean();

    const attendance =
        records
            .filter(record => record.attendance)
            .filter(record => !sessionDate || (
                (!sessionDate.$gte || new Date(record.attendance.sessionDate) >= sessionDate.$gte) &&
                (!sessionDate.$lt || new Date(record.attendance.sessionDate) < sessionDate.$lt)
            ))
            .sort((a, b) => new Date(b.attendance.sessionDate) - new Date(a.attendance.sessionDate));

    const memberships =
        await EnterpriseMember.find(scope(organizationId, { beneficiary: person._id }))
            .populate("enterprise", "enterpriseNumber name")
            .lean();

    const valueReceived = round2(links.reduce((sum, link) => sum + link.value, 0));
    const attendedCount = attendance.filter(record => ["Present", "Late"].includes(record.status)).length;

    return buildReport({
        key: "beneficiary",
        title: fullName(person),
        description: `Beneficiary ${person.beneficiaryNumber}: programs, services received (their own share), training attended and enterprises.`,
        period,
        record: {
            fields: [
                { label: "Beneficiary No.", value: person.beneficiaryNumber },
                { label: "Gender", value: lookupText(person.gender) },
                { label: "Age", value: ageOf(person) },
                { label: "Date of birth", value: person.dateOfBirth, format: "date" },
                { label: "Phone", value: person.phone },
                { label: "Location", value: [person.kebele ? (/kebele/i.test(person.kebele) ? person.kebele : `Kebele ${person.kebele}`) : "", locationText(person)].filter(Boolean).join(", ") },
                { label: "Education", value: lookupText(person.educationLevel) },
                { label: "Occupation", value: lookupText(person.occupation) },
                { label: "Marital status", value: lookupText(person.maritalStatus) },
                { label: "Disability", value: person.isPWD ? (lookupText(person.disabilityType) || "Yes") : "No" },
                { label: "Status", value: person.status }
            ]
        },
        summary: [
            summaryItem("Programs enrolled", enrollments.length),
            summaryItem("Services received", links.length),
            summaryItem("Value received", valueReceived, "money", { currency: "ETB" }),
            summaryItem("Sessions attended", attendedCount),
            summaryItem("Enterprises", memberships.length)
        ],
        sections: [
            section("enrollments", "Programs", [
                column("program", "Program"),
                column("enrolled", "Enrolled on", "date"),
                column("status", "Status"),
                column("completed", "Completed on", "date")
            ], enrollments.map(item => ({
                program: item.program ? `${item.program.programCode} – ${item.program.name}` : "",
                enrolled: item.enrollmentDate,
                status: item.status,
                completed: item.completionDate
            }))),
            section("services", "Services received", [
                column("date", "Date", "date"),
                column("delivery", "Delivery"),
                column("program", "Program"),
                column("services", "What they received"),
                column("value", "Value", "money", { currency: "ETB" })
            ], links
                .sort((a, b) => new Date(b.serviceDelivery.deliveryDate) - new Date(a.serviceDelivery.deliveryDate))
                .map(link => ({
                    id: toId(link.serviceDelivery._id),
                    date: link.serviceDelivery.deliveryDate,
                    delivery: link.serviceDelivery.deliveryNumber,
                    program: link.serviceDelivery.program?.name || "",
                    services: link.items
                        .filter(item => item.quantity > 0)
                        .map(item => `${serviceName(item)} (${quantityText(item, item.quantity)})`)
                        .join("; ") ||
                        (link.serviceDelivery.recipientType !== "Individual" ? `Through ${link.serviceDelivery.recipientName || link.serviceDelivery.recipientType}` : "—"),
                    value: link.value
                })),
            { link: { kind: "delivery", idKey: "id" }, total: { value: valueReceived } }),
            section("attendance", "Training sessions", [
                column("date", "Date", "date"),
                column("activity", "Activity"),
                column("run", "Run"),
                column("session", "Session"),
                column("status", "Status")
            ], attendance.map(record => ({
                date: record.attendance.sessionDate,
                activity: record.activityRun?.activity?.name || "",
                run: record.activityRun?.name || "",
                session: [record.attendance.sessionNumber ? `#${record.attendance.sessionNumber}` : "", record.attendance.sessionTitle].filter(Boolean).join(" "),
                status: record.status
            }))),
            memberships.length
                ? section("enterprises", "Enterprises", [
                    column("enterprise", "Enterprise"),
                    column("role", "Role"),
                    column("joined", "Joined", "date"),
                    column("status", "Status")
                ], memberships.map(item => ({
                    id: toId(item.enterprise?._id),
                    enterprise: item.enterprise ? `${item.enterprise.enterpriseNumber} – ${item.enterprise.name}` : "",
                    role: item.memberRole,
                    joined: item.joinedDate,
                    status: item.status
                })), { link: { kind: "enterprise", idKey: "id" } })
                : null
        ]
    });

};


module.exports = {
    kind: "beneficiary",
    title: "Beneficiary profile",
    generate
};
