// =====================================================
// SERVICE DELIVERIES: SAVED BEHAVIOR + RULE CHECK
// =====================================================
//
// Each service item now stores how it is given out
// (CONSUMPTION / PARTICIPATION), taken from its service
// type when the delivery is saved. This fills it in for
// deliveries saved before, and lists the deliveries that
// break the current rules, so they can be corrected in
// the screen (nothing else is changed):
//
//   - the unit is not one the service type allows
//   - a part quantity (2.5) of a countable unit
//   - a detail item without a unit, or of the other kind
//     (money inside goods, goods inside money)
//   - detail items that don't add up to the item's cost
//   - "Individual" allocation with people who have no share,
//     or money (cash, fees) not shared out in full
//
//   node scripts/repairServiceDeliveries.js            (apply)
//   node scripts/repairServiceDeliveries.js --dry-run  (only report)
//
// Live database:
//   node scripts/repairServiceDeliveries.js --uri-file .env.atlas --db ngo_system --dry-run
//
// Safe to re-run: only empty behaviors are filled.
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const {
    connectForScript
} = require("../utils/scriptConnection");

const {
    getUnitSemantics,
    allowsDecimalQuantity
} = require("../config/serviceDeliveryUnits");


const DRY_RUN = process.argv.includes("--dry-run");

const BEHAVIORS = ["CONSUMPTION", "PARTICIPATION"];

const roundMoney = (value) =>
    Math.round(Number(value || 0) * 100) / 100;

const label = (lookup) =>
    lookup?.value || lookup?.name || lookup?.code || "(unknown)";

// The unit's own type first; codes / names for old units
const semanticsOf = (unit) => {
    const type = String(unit?.semanticType || "").toLowerCase();
    if (type === "monetary" || type === "physical") return type;
    for (const candidate of [unit?.code, unit?.value, unit?.name]) {
        const found = candidate ? getUnitSemantics(candidate) : "unknown";
        if (found !== "unknown") return found;
    }
    return "unknown";
};


const main = async () => {

    await connectForScript();

    const db = mongoose.connection.db;

    console.log(`Database: ${mongoose.connection.name}${DRY_RUN ? " (dry run)" : ""}`);

    const deliveries =
        await db.collection("servicedeliveries")
            .find({ isDeleted: { $ne: true } })
            .toArray();

    // every lookup the deliveries use, loaded once
    const lookupIds = new Set();
    for (const delivery of deliveries) {
        for (const item of delivery.items || []) {
            for (const id of [item.serviceType, item.unit]) if (id) lookupIds.add(String(id));
            for (const detail of item.detailItems || []) {
                for (const id of [detail.unit, detail.allocationUnit]) if (id) lookupIds.add(String(id));
            }
        }
    }

    const lookups =
        new Map(
            (await db.collection("lookups")
                .find({ _id: { $in: [...lookupIds].map(id => new mongoose.Types.ObjectId(id)) } })
                .toArray())
                .map(lookup => [String(lookup._id), lookup])
        );

    const get = (id) => (id ? lookups.get(String(id)) : null);

    let filled = 0;
    const problems = [];

    for (const delivery of deliveries) {

        const name = `${delivery.deliveryNumber || delivery._id}`;
        const issues = [];
        const set = {};

        (delivery.items || []).forEach((item, index) => {

            const serviceType = get(item.serviceType);
            const unit = get(item.unit);
            const itemName = label(serviceType);

            // ---------- saved behavior ----------
            if (!BEHAVIORS.includes(item.allocationBehavior)) {
                const behavior = String(serviceType?.allocationBehavior || "").toUpperCase();
                set[`items.${index}.allocationBehavior`] = BEHAVIORS.includes(behavior) ? behavior : "CONSUMPTION";
            }

            // ---------- item rules ----------
            const allowed = (serviceType?.allowedUnits || []).map(String);
            if (unit && allowed.length && !allowed.includes(String(unit._id))) {
                issues.push(`${itemName}: unit ${label(unit)} is not allowed for this service type`);
            }

            if (unit && !allowsDecimalQuantity(unit) && !Number.isInteger(Number(item.quantity))) {
                issues.push(`${itemName}: ${item.quantity} ${label(unit)} (whole numbers only)`);
            }

            const itemSemantics = semanticsOf(unit);
            const details = item.detailItems || [];

            for (const detail of details) {
                const detailName = detail.name || "a detail item";
                const detailUnit = get(detail.unit);
                if (!detailUnit) {
                    issues.push(`${itemName} / ${detailName}: no unit`);
                    continue;
                }
                const detailSemantics = semanticsOf(detailUnit);
                if (itemSemantics !== "unknown" && detailSemantics !== "unknown" && detailSemantics !== itemSemantics) {
                    issues.push(`${itemName} / ${detailName}: ${itemSemantics === "monetary" ? "goods inside an amount of money" : "money inside goods"}`);
                }
                if (!allowsDecimalQuantity(detailUnit) && !Number.isInteger(Number(detail.quantity))) {
                    issues.push(`${itemName} / ${detailName}: ${detail.quantity} ${label(detailUnit)} (whole numbers only)`);
                }
            }

            if (details.length) {
                const itemTotal = roundMoney(Number(item.quantity || 0) * Number(item.unitCost || 0));
                const detailTotal = roundMoney(details.reduce((sum, detail) => sum + Number(detail.quantity || 0) * Number(detail.unitCost || 0), 0));
                if (Math.abs(itemTotal - detailTotal) > 0.01) {
                    issues.push(`${itemName}: detail items add up to ${detailTotal}, the item costs ${itemTotal}`);
                }
            }

        });

        // ---------- Individual: everyone has a share ----------
        if ((delivery.recipientType || "Individual") === "Individual" && delivery.allocationMethod === "Individual") {
            const links = await db.collection("servicedeliverybeneficiaries")
                .find({ serviceDelivery: delivery._id }, { projection: { allocations: 1 } })
                .toArray();
            const without = links.filter(link => !(link.allocations || []).length).length;
            if (without) issues.push(`Individual allocation, but ${without} of ${links.length} beneficiaries have no share`);

            // money is shared out in full
            (delivery.items || []).forEach((item, index) => {
                if (semanticsOf(get(item.unit)) !== "monetary") return;
                const cost = roundMoney(Number(item.quantity || 0) * Number(item.unitCost || 0));
                const given = roundMoney(links.reduce((sum, link) => sum + (link.allocations || [])
                    .filter(allocation => String(allocation.serviceItem) === String(item._id))
                    .reduce((total, allocation) => total + Number(allocation.allocatedValue || 0), 0), 0));
                if (Math.abs(cost - given) > 0.01) issues.push(`Service item ${index + 1}: ${cost} in money, shares add up to ${given} (${roundMoney(cost - given)} with no one)`);
            });
        }

        if (Object.keys(set).length) {
            filled++;
            if (!DRY_RUN) {
                await db.collection("servicedeliveries").updateOne({ _id: delivery._id }, { $set: set });
            }
        }

        if (issues.length) problems.push({ name, title: delivery.title || delivery.name || "", issues });

    }

    console.log(`\n${filled} of ${deliveries.length} deliveries ${DRY_RUN ? "would get" : "got"} the item behavior filled in.`);

    if (problems.length) {
        console.log(`\n${problems.length} deliveries break the current rules (correct them in the screen):`);
        for (const problem of problems) {
            console.log(`  ${problem.name}  ${problem.title}`);
            for (const issue of problem.issues) console.log(`    - ${issue}`);
        }
    }
    else {
        console.log("\nAll deliveries follow the current rules.");
    }

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
