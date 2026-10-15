import activityRunReducer
from "./activityRunSlice";


export {

    getActivityRunsThunk,

    getActivityRunByIdThunk,

    createActivityRunThunk,

    updateActivityRunThunk,

    deleteActivityRunThunk

}
from "./activityRunThunks";


export default activityRunReducer;