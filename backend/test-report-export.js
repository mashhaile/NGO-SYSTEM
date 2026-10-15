const mongoose = require("mongoose");

const ServiceDelivery =
    require("./models/ServiceDelivery");

const MONGO_URI =
    process.env.MONGO_URI ||
    "mongodb://127.0.0.1:27017/ngo-system";

const run = async () => {
    try {
        await mongoose.connect(MONGO_URI);

        console.log("MongoDB connected");

        const delivery =
            await ServiceDelivery.findOne({
                deliveryNumber: "SD-000063"
            }).lean();

        if (!delivery) {
            throw new Error(
                "SD-000063 was not found"
            );
        }

        console.log(
            "\n========================================"
        );
        console.log(
            "SERVICE DELIVERY TOP LEVEL KEYS"
        );
        console.log(
            "========================================"
        );

        console.log(
            Object.keys(delivery)
        );

        console.log(
            "\n========================================"
        );
        console.log(
            "SERVICE ITEMS"
        );
        console.log(
            "========================================"
        );

        console.dir(
            delivery.serviceItems,
            {
                depth: 12,
                colors: false
            }
        );

        console.log(
            "\n========================================"
        );
        console.log(
            "ALLOCATIONS"
        );
        console.log(
            "========================================"
        );

        console.dir(
            delivery.allocations,
            {
                depth: 12,
                colors: false
            }
        );

        console.log(
            "\n========================================"
        );
        console.log(
            "BENEFICIARIES"
        );
        console.log(
            "========================================"
        );

        console.dir(
            delivery.beneficiaries,
            {
                depth: 12,
                colors: false
            }
        );

        console.log(
            "\n========================================"
        );
        console.log(
            "BENEFICIARY RECORDS"
        );
        console.log(
            "========================================"
        );

        console.dir(
            delivery.beneficiaryRecords,
            {
                depth: 12,
                colors: false
            }
        );

        console.log(
            "\n========================================"
        );
        console.log(
            "RECIPIENTS"
        );
        console.log(
            "========================================"
        );

        console.dir(
            delivery.recipients,
            {
                depth: 12,
                colors: false
            }
        );

        console.log(
            "\n========================================"
        );
        console.log(
            "ALL POSSIBLE ALLOCATION FIELDS"
        );
        console.log(
            "========================================"
        );

        for (const key of Object.keys(delivery)) {
            const value = delivery[key];

            if (
                Array.isArray(value) &&
                value.length > 0
            ) {
                const first = value[0];

                if (
                    first &&
                    typeof first === "object"
                ) {
                    const keys =
                        Object.keys(first);

                    const allocationLike =
                        keys.some(key =>
                            [
                                "quantity",
                                "allocatedValue",
                                "beneficiary",
                                "serviceItem",
                                "detailItem"
                            ].includes(key)
                        );

                    if (allocationLike) {
                        console.log(
                            `\nFIELD: ${key}`
                        );

                        console.dir(
                            value,
                            {
                                depth: 8,
                                colors: false
                            }
                        );
                    }
                }
            }
        }

    } catch (error) {
        console.error(
            "\nTEST FAILED:"
        );

        console.error(error);

        process.exitCode = 1;

    } finally {
        await mongoose.disconnect();
    }
};

run();