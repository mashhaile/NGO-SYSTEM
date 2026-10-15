import {
    Link
} from "react-router-dom";

import {
    Button,
    Chip
} from "@mui/material";


// ==========================================================
// LOOKUP TABLE
// ==========================================================

const LookupTable = ({
    lookups = [],
    onDelete,
    deletingId = null
}) => {


    // ======================================================
    // RENDER
    // ======================================================

    return (

        <div
            style={{
                width: "100%",
                overflowX: "auto"
            }}
        >

            <table
                style={{
                    width: "100%",
                    borderCollapse: "collapse"
                }}
            >

                {/* ==================================================
                    HEADER
                ================================================== */}

                <thead>

                    <tr>

                        <th
                            style={{
                                textAlign: "left",
                                padding: "12px"
                            }}
                        >
                            Value
                        </th>


                        <th
                            style={{
                                textAlign: "left",
                                padding: "12px"
                            }}
                        >
                            Code
                        </th>


                        <th
                            style={{
                                textAlign: "left",
                                padding: "12px"
                            }}
                        >
                            Status
                        </th>


                        <th
                            style={{
                                textAlign: "right",
                                padding: "12px"
                            }}
                        >
                            Actions
                        </th>

                    </tr>

                </thead>


                {/* ==================================================
                    BODY
                ================================================== */}

                <tbody>

                    {lookups.length === 0 ? (

                        <tr>

                            <td
                                colSpan={4}
                                style={{
                                    textAlign: "center",
                                    padding: "30px"
                                }}
                            >
                                No values found
                            </td>

                        </tr>

                    ) : (

                        lookups.map(
                            (lookup) => {

                                const isActive =
                                    lookup?.active !== false;

                                const isDeleting =
                                    deletingId ===
                                    lookup?._id;


                                return (

                                    <tr
                                        key={
                                            lookup?._id
                                        }
                                    >

                                        {/* ==========================================
                                            VALUE
                                        ========================================== */}

                                        <td
                                            style={{
                                                padding: "12px",
                                                fontWeight: 500
                                            }}
                                        >
                                            {
                                                lookup?.value ||
                                                "-"
                                            }
                                        </td>


                                        {/* ==========================================
                                            CODE
                                        ========================================== */}

                                        <td
                                            style={{
                                                padding: "12px"
                                            }}
                                        >
                                            {
                                                lookup?.code ||
                                                "-"
                                            }
                                        </td>


                                        {/* ==========================================
                                            STATUS
                                        ========================================== */}

                                        <td
                                            style={{
                                                padding: "12px"
                                            }}
                                        >

                                            <Chip
                                                label={
                                                    isActive
                                                        ? "Active"
                                                        : "Inactive"
                                                }
                                                size="small"
                                                color={
                                                    isActive
                                                        ? "success"
                                                        : "default"
                                                }
                                                variant={
                                                    isActive
                                                        ? "filled"
                                                        : "outlined"
                                                }
                                            />

                                        </td>


                                        {/* ==========================================
                                            ACTIONS
                                        ========================================== */}

                                        <td
                                            style={{
                                                padding: "12px",
                                                textAlign: "right",
                                                whiteSpace: "nowrap"
                                            }}
                                        >

                                            {/* EDIT */}

                                            <Button
                                                component={
                                                    Link
                                                }
                                                to={`/lookups/${lookup?._id}/edit`}
                                                size="small"
                                                variant="outlined"
                                                sx={{
                                                    mr: 1
                                                }}
                                            >
                                                Edit
                                            </Button>


                                            {/* DEACTIVATE */}

                                            <Button
                                                size="small"
                                                color="error"
                                                variant="outlined"
                                                disabled={
                                                    isDeleting ||
                                                    !isActive
                                                }
                                                onClick={() => {

                                                    if (
                                                        onDelete &&
                                                        lookup?._id
                                                    ) {

                                                        onDelete(
                                                            lookup
                                                        );

                                                    }

                                                }}
                                            >

                                                {
                                                    isDeleting
                                                        ? "Deactivating..."
                                                        : isActive
                                                            ? "Deactivate"
                                                            : "Inactive"
                                                }

                                            </Button>

                                        </td>

                                    </tr>

                                );

                            }
                        )

                    )}

                </tbody>

            </table>

        </div>

    );

};


export default LookupTable;