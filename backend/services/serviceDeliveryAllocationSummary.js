// =====================================================
// SERVICE DELIVERY: ALLOCATION SUMMARY
// =====================================================
//
// One calculation of what was delivered, what was given to
// whom and what is left, used by the delivery's detail
// page (and matching the rules applied when it is saved):
//
//   An item is shared out either as itself or by its detail
//   items. Detail items are counted in the unit they are
//   given out in (1 sack = 50 kg: 2 sacks = 100 kg), so
//   144 packs stay 144 packs.
//
//   Goods used up (consumption) reduce what is left; a
//   training (participation) is taken part in by everyone,
//   so it does not run out: it is counted as "3 sessions,
//   4 participants", never 12 sessions.
//
//   Money (cash, fees) is counted by amount, not quantity.
//
//   Individual deliveries: people with no share of their
//   own share equally what the others' shares leave.
//
// =====================================================

const round = (value, digits = 2) => {
    const factor = 10 ** digits;
    return Math.round(Number(value || 0) * factor) / factor;
};

const toNumber = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : 0;
};

const toId = (value) =>
    value && typeof value === "object" ? String(value._id || value) : value ? String(value) : "";

const MONEY_CODES = ["ETB", "BIRR", "USD", "EUR"];

const isMoney = (unit) =>
    String(unit?.semanticType || "").toLowerCase() === "monetary" ||
    MONEY_CODES.includes(String(unit?.code || unit?.value || "").toUpperCase());

const unitName = (unit) => unit?.value || unit?.name || unit?.code || "";

// "Pack" / "Packs" for a quantity
const unitLabel = (unit, quantity) => {
    const name = unitName(unit);
    if (!name || Math.abs(toNumber(quantity)) === 1 || /s$/i.test(name)) return name;
    if (/^(kg|g|l|ml|km|m|etb|birr|usd|eur)$/i.test(name)) return name;
    return `${name}s`;
};

const quantityText = (quantity, unit) =>
    `${round(quantity, 3).toLocaleString("en-US")} ${unitLabel(unit, quantity)}`.trim();

const addByUnit = (map, unit, quantity) => {
    if (!unit || !(toNumber(quantity) > 0)) return;
    const key = toId(unit) || unitName(unit);
    const entry = map.get(key) || { unit, quantity: 0 };
    entry.quantity = round(entry.quantity + toNumber(quantity), 3);
    map.set(key, entry);
};

const byUnitList = (map) =>
    [...map.values()].map(entry => ({ unit: unitName(entry.unit), quantity: entry.quantity, text: quantityText(entry.quantity, entry.unit) }));


const summarize = (delivery, links = []) => {

    const items = Array.isArray(delivery?.items) ? delivery.items : [];
    const records = Array.isArray(links) ? links : [];
    const individual = (delivery?.recipientType || "Individual") === "Individual";

    const allAllocations = records.flatMap(record => Array.isArray(record.allocations) ? record.allocations : []);

    const allocatedByUnit = new Map();
    const remainingByUnit = new Map();
    const participation = [];

    const itemRows = items.map((item, index) => {

        const itemId = toId(item._id);
        const unit = item.unit;
        const money = isMoney(unit);
        const behavior = String(item.allocationBehavior || item.serviceType?.allocationBehavior || "CONSUMPTION").toUpperCase();
        const delivered = toNumber(item.quantity);
        const cost = round(toNumber(item.totalCost) || delivered * toNumber(item.unitCost));
        const own = allAllocations.filter(allocation => toId(allocation.serviceItem) === itemId);
        const direct = own.filter(allocation => !allocation.detailItem);
        const byDetail = own.filter(allocation => allocation.detailItem);
        const level = byDetail.length ? "detail" : direct.length ? "item" : null;
        const allocatedValue = round(own.reduce((sum, allocation) => sum + toNumber(allocation.allocatedValue), 0));
        const participants = new Set(records.filter(record => (record.allocations || []).some(allocation => toId(allocation.serviceItem) === itemId)).map(record => toId(record.beneficiary))).size;

        // ---------- detail items, in the unit they are given out in ----------
        const details = (item.detailItems || []).map(detail => {
            const detailId = toId(detail._id);
            const given = detail.allocationUnit && toId(detail.allocationUnit) ? detail.allocationUnit : detail.unit;
            const factor = detail.allocationUnit && toId(detail.allocationUnit) ? toNumber(detail.allocationConversionFactor) || 1 : 1;
            const capacity = round(toNumber(detail.quantity) * factor, 3);
            const detailMoney = isMoney(detail.unit);
            const ownDetail = byDetail.filter(allocation => toId(allocation.detailItem) === detailId);
            const allocated = round(ownDetail.reduce((sum, allocation) => sum + toNumber(allocation.quantity), 0), 3);
            const detailCost = round(toNumber(detail.totalCost) || toNumber(detail.quantity) * toNumber(detail.unitCost));
            const detailValue = round(ownDetail.reduce((sum, allocation) => sum + toNumber(allocation.allocatedValue), 0));
            const consumed = behavior === "CONSUMPTION" && !detailMoney;
            return {
                detailId,
                name: detail.name || "",
                money: detailMoney,
                unit: unitName(given),
                deliveredText: factor !== 1
                    ? `${quantityText(detail.quantity, detail.unit)} = ${quantityText(capacity, given)}`
                    : quantityText(capacity, given),
                capacity: detailMoney ? null : capacity,
                allocated: detailMoney ? null : allocated,
                allocatedText: detailMoney ? "—" : quantityText(allocated, given),
                remaining: consumed ? round(Math.max(capacity - allocated, 0), 3) : null,
                remainingText: consumed ? quantityText(Math.max(capacity - allocated, 0), given) : detailMoney ? "—" : "Taken part in by everyone",
                over: consumed ? round(Math.max(allocated - capacity, 0), 3) : 0,
                unitPrice: factor ? round(toNumber(detail.unitCost) / factor, 4) : 0,
                cost: detailCost,
                allocatedValue: detailValue,
                unallocatedValue: round(Math.max(detailCost - detailValue, 0)),
                _given: given
            };
        });

        // ---------- the item ----------
        let remaining = null;
        let allocated = null;

        const whole = !individual;

        if (!money && whole) {
            // a household, group or institution received all of it
            addByUnit(allocatedByUnit, unit, delivered);
        }
        else if (!money) {
            if (behavior === "PARTICIPATION") {
                participation.push({ item: item.serviceType?.value || `Service item ${index + 1}`, text: `${quantityText(delivered, unit)}, ${participants} participant${participants === 1 ? "" : "s"}` });
            }
            else if (level === "detail" || (!level && details.length)) {
                // shared out by detail items: what is left is per detail
                for (const detail of details) {
                    if (detail.money) continue;
                    addByUnit(allocatedByUnit, detail._given, detail.allocated);
                    addByUnit(remainingByUnit, detail._given, detail.remaining);
                }
            }
            else {
                allocated = round(direct.reduce((sum, allocation) => sum + toNumber(allocation.quantity), 0), 3);
                remaining = round(Math.max(delivered - allocated, 0), 3);
                addByUnit(allocatedByUnit, unit, allocated);
                addByUnit(remainingByUnit, unit, remaining);
            }
        }

        return {
            itemId,
            name: item.serviceType?.value || `Service item ${index + 1}`,
            behavior,
            money,
            level,
            unit: unitName(unit),
            deliveredText: money ? `${unitName(unit)} ${round(cost).toLocaleString("en-US", { minimumFractionDigits: 2 })}` : quantityText(delivered, unit),
            allocatedText:
                whole ? `To the ${String(delivery.recipientType).toLowerCase()} as a whole`
                    : money ? "—"
                    : behavior === "PARTICIPATION" ? `${participants} participant${participants === 1 ? "" : "s"}`
                        : level === "detail" ? "By detail items"
                            : quantityText(allocated || 0, unit),
            remainingText:
                whole || money ? "—"
                    : behavior === "PARTICIPATION" ? "Taken part in by everyone"
                        : level === "detail" || (!level && details.length) ? "See detail items"
                            : quantityText(remaining || 0, unit),
            participants,
            cost,
            allocatedValue,
            unallocatedValue: round(Math.max(cost - allocatedValue, 0)),
            details: details.map(({ _given, ...detail }) => detail)
        };

    });

    // ---------- money ----------
    const cost = round(itemRows.reduce((sum, row) => sum + row.cost, 0));
    const allocatedValue = round(itemRows.reduce((sum, row) => sum + row.allocatedValue, 0));
    const left = round(Math.max(cost - allocatedValue, 0));
    const peopleWithoutShare = individual ? records.filter(record => !(record.allocations || []).length).length : 0;
    const sharedEqually = peopleWithoutShare ? left : 0;

    return {
        recipient: individual ? "people" : delivery.recipientType,
        cost,
        allocatedValue,
        sharedEqually,
        peopleWithoutShare,
        equalShare: peopleWithoutShare ? round(sharedEqually / peopleWithoutShare) : 0,
        // value no one received: individual deliveries only
        unallocatedValue: individual ? round(left - sharedEqually) : 0,
        // a household, group or institution receives the whole value
        toRecipientAsWhole: individual ? 0 : cost,
        allocatedQuantities: byUnitList(allocatedByUnit),
        remainingQuantities: byUnitList(remainingByUnit),
        participation,
        items: itemRows
    };

};


module.exports = {
    summarize
};
