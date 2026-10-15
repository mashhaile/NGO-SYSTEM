import { useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";

import {
  Box,
  Card,
  CardContent,
  Typography,
  Stack,
  Button
} from "@mui/material";

import { ArrowBack } from "@mui/icons-material";

import ActivityRunForm from "../components/ActivityRunForm";

import {
  getActivityRunByIdThunk,
  updateActivityRunThunk
} from "../store";

const ActivityRunEditPage = () => {
  const { id } = useParams();

  const navigate = useNavigate();

  const dispatch = useDispatch();

  const {
    current,
    loading
  } = useSelector((state) => state.activityRuns);

  useEffect(() => {
    dispatch(getActivityRunByIdThunk(id));
  }, [dispatch, id]);

  const handleSubmit = async (data) => {
    try {
      await dispatch(
        updateActivityRunThunk({
          id,
          data
        })
      ).unwrap();

      navigate("/activity-runs");
    } catch (error) {
      console.error("Update Activity Run Error:", error);
    }
  };

  if (loading && !current) {
    return <Typography>Loading...</Typography>;
  }

  return (
    <Box>
      <Stack
        direction="row"
        justifyContent="space-between"
        mb={3}
      >
        <Typography
          variant="h4"
          fontWeight={700}
        >
          Edit Activity Run
        </Typography>

        <Button
          variant="outlined"
          startIcon={<ArrowBack />}
          onClick={() => navigate("/activity-runs")}
        >
          Back
        </Button>
      </Stack>

      <Card>
        <CardContent>
          <ActivityRunForm
            initialData={current}
            onSubmit={handleSubmit}
            loading={loading}
          />
        </CardContent>
      </Card>
    </Box>
  );
};

export default ActivityRunEditPage;