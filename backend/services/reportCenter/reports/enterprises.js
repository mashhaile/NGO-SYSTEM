// =====================================================
// ENTERPRISES REPORT
// =====================================================
//
// Enterprises and their members (beneficiaries), and the
// support the members received: each member's own share
// of every delivery. Replaces the Enterprise, Enterprise
// Participation and Enterprise Impact reports.
//
// Filters: region, status
//
// =====================================================

const Enterprise = require("../../../models/Enterprise");
const EnterpriseMember = require("../../../models/EnterpriseMember");

const {
    scope, toId, round2, percent, lookupText, locationText, fullName, groupRows,
    summaryItem, column, section, buildReport
} = require("../core");

const { loadDeliveries, loadServedLinks } = require("../data");


// all enterprises with their members and what the members received
const loadEnterpriseSupport = async (organizationId, period, enterpriseFilter = {}) => {

    const enterprises =
        await Enterprise.find(scope(organizationId, enterpriseFilter))
            .populate("enterpriseType", "value")
            .populate("ownershipType", "value")
            .populate("businessSector", "value")
            .sort({ enterpriseNumber: 1 })
            .lean();

    const members =
        await EnterpriseMember.find(scope(organizationId, { enterprise: { $in: enterprises.map(item => item._id) } }))
            .populate({ path: "beneficiary", select: "beneficiaryNumber firstName middleName lastName gender", populate: { path: "gender", select: "value" } })
            .lean();

    const memberIds = [...new Set(members.map(member => toId(member.beneficiary?._id)).filter(Boolean))];

    const deliveries = memberIds.length ? await loadDeliveries(organizationId, period) : [];
    const links =
        memberIds.length
            ? (await loadServedLinks(organizationId, deliveries)).filter(link => memberIds.includes(link.beneficiaryId))
            : [];

    return { enterprises, members, links };

};


const generate = async (query, context, period) => {

    const { organizationId } = context;

    const filter = {};
    if (query.region) filter.$or = [{ region: query.region }, { regionCode: query.region }];
    if (query.status) filter.status = query.status;

    const { enterprises, members, links } = await loadEnterpriseSupport(organizationId, period, filter);

    const rows = enterprises.map(enterprise => {
        const own = members.filter(member => toId(member.enterprise) === toId(enterprise._id));
        const ids = new Set(own.map(member => toId(member.beneficiary?._id)));
        const support = links.filter(link => ids.has(link.beneficiaryId));
        return {
            enterprise,
            id: toId(enterprise._id),
            number: enterprise.enterpriseNumber,
            name: enterprise.name,
            type: lookupText(enterprise.enterpriseType),
            sector: lookupText(enterprise.businessSector),
            ownership: lookupText(enterprise.ownershipType),
            location: locationText(enterprise),
            members: own.length,
            active: own.filter(member => member.status !== "Inactive").length,
            women: own.filter(member => /^female$/i.test(lookupText(member.beneficiary?.gender))).length,
            supported: new Set(support.map(link => link.beneficiaryId)).size,
            deliveries: new Set(support.map(link => toId(link.serviceDelivery._id))).size,
            value: round2(support.reduce((sum, link) => sum + link.value, 0)),
            status: enterprise.status || ""
        };
    });

    const totalMembers = rows.reduce((sum, row) => sum + row.members, 0);
    const totalWomen = rows.reduce((sum, row) => sum + row.women, 0);
    const value = round2(rows.reduce((sum, row) => sum + row.value, 0));

    const measures = {
        enterprises: () => 1,
        members: row => row.members,
        value: row => row.value
    };

    const breakdownColumns = (first) => [
        column("label", first),
        column("enterprises", "Enterprises", "number"),
        column("members", "Members", "number"),
        column("value", "Support to members", "money", { currency: "ETB" })
    ];

    return buildReport({
        key: "enterprises",
        title: "Enterprises",
        description: "Enterprises, their members, and the support members received (each member's own share).",
        period,
        summary: [
            summaryItem("Enterprises", rows.length),
            summaryItem("Members", totalMembers, "number", { note: `${rows.reduce((sum, row) => sum + row.active, 0)} active` }),
            summaryItem("Women members", totalWomen, "number", { note: `${percent(totalWomen, totalMembers)}%` }),
            summaryItem("Members supported in the period", rows.reduce((sum, row) => sum + row.supported, 0)),
            summaryItem("Support to members", value, "money", { currency: "ETB" }),
            summaryItem("Average per enterprise", rows.length ? round2(value / rows.length) : 0, "money", { currency: "ETB" })
        ],
        sections: [
            section("type", "By enterprise type", breakdownColumns("Type"), groupRows(rows, row => row.type, measures)),
            section("sector", "By business sector", breakdownColumns("Sector"), groupRows(rows, row => row.sector, measures),
                { chart: { type: "bar", x: "label", series: ["members"], yLabel: "Members" } }),
            section("location", "By location", breakdownColumns("Woreda, zone, region"), groupRows(rows, row => row.location, measures)),
            section("roles", "Members by role", [column("label", "Role"), column("members", "Members", "number")],
                groupRows(members, member => member.memberRole, { members: () => 1 }))
        ],
        details: {
            title: "Enterprises",
            link: { kind: "enterprise", idKey: "id" },
            columns: [
                column("number", "No."),
                column("name", "Enterprise"),
                column("type", "Type"),
                column("sector", "Sector"),
                column("location", "Location"),
                column("members", "Members", "number"),
                column("women", "Women", "number"),
                column("supported", "Members supported", "number"),
                column("deliveries", "Deliveries", "number"),
                column("value", "Support to members", "money", { currency: "ETB" }),
                column("status", "Status")
            ],
            rows: rows.map(({ enterprise, ...row }) => row)
        }
    });

};


module.exports = {
    key: "enterprises",
    title: "Enterprises",
    description: "Enterprises and their members, and the support members received.",
    filters: ["region", "status"],
    detail: "enterprise",
    generate,
    loadEnterpriseSupport,
    fullName
};
