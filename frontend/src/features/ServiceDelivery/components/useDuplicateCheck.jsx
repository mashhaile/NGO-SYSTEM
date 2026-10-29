import {
    useRef,
    useState
} from "react";

import {
    Alert,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableRow
} from "@mui/material";

import {
    AppButton,
    AppTextField
} from "../../../components/ui";

import { formatDate } from "../../../utils/date";


// =====================================================
// DUPLICATE CHECK (humanitarian module)
// =====================================================
//
// When the server refuses a delivery because the same
// people already received the same service in the period
// (409 DUPLICATE_DELIVERY), this shows who, what and when,
// and lets the user go back or save anyway with a reason.
//
//   const [saveChecked, duplicateDialog] = useDuplicateCheck();
//   await saveChecked(payload => createApi(payload), payload);
//   ... {duplicateDialog}
//
// Going back rejects with { cancelled: true }.
//
// =====================================================

const isDuplicate = (error) =>
    error?.response?.status === 409 &&
    Array.isArray(error.response.data?.errors) &&
    error.response.data.errors.some(item => item?.code === "DUPLICATE_DELIVERY");


const useDuplicateCheck = () => {

    const [state, setState] = useState(null);
    const [reason, setReason] = useState("");
    const answer = useRef(null);

    const ask = (message, rows) =>
        new Promise(resolve => {
            answer.current = resolve;
            setReason("");
            setState({ message, rows });
        });

    const close = (value) => {
        setState(null);
        answer.current?.(value);
        answer.current = null;
    };

    const saveChecked = async (save, payload) => {
        try {
            return await save(payload);
        }
        catch (error) {
            if (!isDuplicate(error)) throw error;
            const given = await ask(error.response.data.message, error.response.data.errors);
            if (!given) {
                const cancelled = new Error("Not saved.");
                cancelled.cancelled = true;
                throw cancelled;
            }
            return save({ ...payload, confirmDuplicates: true, duplicateReason: given });
        }
    };

    const dialog = (
        <Dialog open={Boolean(state)} onClose={() => close(null)} fullWidth maxWidth="md">
            <DialogTitle sx={{ fontWeight: 700 }}>Already received in this period</DialogTitle>
            <DialogContent>
                <Alert severity="warning" sx={{ mb: 2 }}>{state?.message}</Alert>
                <Table size="small">
                    <TableHead>
                        <TableRow>
                            <TableCell>Person</TableCell>
                            <TableCell>Service</TableCell>
                            <TableCell>Earlier delivery</TableCell>
                            <TableCell>Date</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {(state?.rows || []).map((row, index) => (
                            <TableRow key={index}>
                                <TableCell>{row.name}{row.beneficiaryNumber ? ` (${row.beneficiaryNumber})` : ""}</TableCell>
                                <TableCell>{row.serviceType}</TableCell>
                                <TableCell>{row.deliveryNumber}</TableCell>
                                <TableCell>{formatDate(row.deliveryDate)}</TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
                <AppTextField
                    sx={{ mt: 2 }}
                    label="Reason for giving it again (to save anyway)"
                    multiline
                    rows={2}
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder="e.g. Second kit for a newborn; the first one was lost in the flood"
                />
            </DialogContent>
            <DialogActions sx={{ px: 3, pb: 2 }}>
                <AppButton variant="outlined" onClick={() => close(null)}>Go Back and Change</AppButton>
                <AppButton variant="contained" color="warning" disabled={reason.trim().length < 3} onClick={() => close(reason.trim())}>
                    Save Anyway
                </AppButton>
            </DialogActions>
        </Dialog>
    );

    return [saveChecked, dialog];

};


export default useDuplicateCheck;
