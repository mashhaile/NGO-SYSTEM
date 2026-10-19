// =====================================================
// SERVICE DELIVERY STATUS
// =====================================================
//
// Delivered:
//     The service was provided. Counted in reports.
//
// Cancelled:
//     The delivery did not happen or was recorded in
//     error. Kept for audit, excluded from report
//     totals, and locked until set back to Delivered.
//
// =====================================================

const SERVICE_DELIVERY_STATUS = {

    DELIVERED:
        "Delivered",

    CANCELLED:
        "Cancelled"

};


const SERVICE_DELIVERY_STATUSES =
    Object.values(
        SERVICE_DELIVERY_STATUS
    );


const DEFAULT_SERVICE_DELIVERY_STATUS =
    SERVICE_DELIVERY_STATUS.DELIVERED;


// Query condition for deliveries that count toward
// reports, dashboards and impact figures.

const COUNTED_DELIVERY_FILTER = {

    status: {
        $ne:
            SERVICE_DELIVERY_STATUS.CANCELLED
    }

};


module.exports = {
    SERVICE_DELIVERY_STATUS,
    SERVICE_DELIVERY_STATUSES,
    DEFAULT_SERVICE_DELIVERY_STATUS,
    COUNTED_DELIVERY_FILTER
};
