import {
    lazy,
    Suspense
} from "react";

import {
    Routes,
    Route,
    Navigate
} from "react-router-dom";


// ==========================================================
// LAYOUT / ROUTE GUARDS
// ==========================================================

import DashboardLayout
    from "../layouts/components/DashboardLayout";

import {
    LoadingState
} from "../components/ui";

import ProtectedRoute
    from "./ProtectedRoute";

import PermissionRoute
    from "./PermissionRoute";

import SuperAdminRoute
    from "./SuperAdminRoute";


// ==========================================================
// AUTH
// ==========================================================

import {
    LoginPage
} from "../features/auth";


// ==========================================================
// NORMAL DASHBOARD
// ==========================================================



// ==========================================================
// SUPER ADMIN
// ==========================================================



// ==========================================================
// ORGANIZATION SETTINGS
// ==========================================================



// ==========================================================
// CUSTOM FIELDS
// ==========================================================





// ==========================================================
// PROGRAMS
// ==========================================================



// ==========================================================
// BENEFICIARIES
// ==========================================================




// ==========================================================
// ENTERPRISES
// ==========================================================









// ==========================================================
// PROJECTS
// ==========================================================



// ==========================================================
// ACTIVITIES
// ==========================================================






// ==========================================================
// ACTIVITY RUNS
// ==========================================================



// ==========================================================
// TERMS OF REFERENCE
// ==========================================================



// ==========================================================
// ATTENDANCE
// ==========================================================






// ==========================================================
// ENROLLMENTS
// ==========================================================



// ==========================================================
// SERVICE DELIVERY
// ==========================================================



// ==========================================================
// LOOKUPS
// ==========================================================






// ==========================================================
// USERS
// ==========================================================



// ==========================================================
// DONORS
// ==========================================================






// ==========================================================
// DONATIONS
// ==========================================================










    // ==========================================================
// REPORTS
// ==========================================================


// ==========================================================
// APP ROUTES
// ==========================================================

// ==========================================================
// PAGES (loaded on demand)
// ==========================================================
//
// Each page is its own file, downloaded the first time it
// is opened. After a new deploy an open tab may ask for a
// file that no longer exists: reload once to get the new
// version instead of showing an error.
//
const lazyPage = (load) =>
    lazy(() =>
        load()
            .then(module => {
                sessionStorage.removeItem("page-reload");
                return module;
            })
            .catch(error => {
                if (!sessionStorage.getItem("page-reload")) {
                    sessionStorage.setItem("page-reload", "1");
                    window.location.reload();
                    return new Promise(() => {});
                }
                throw error;
            })
    );

const DashboardPage = lazyPage(() => import("../features/dashboard/pages/DashboardPage"));
const OrganizationSettingsPage = lazyPage(() => import("../features/organizations/pages/OrganizationSettingsPage"));
const CustomFieldListPage = lazyPage(() => import("../features/customfields/pages/CustomFieldListPage"));
const CustomFieldCreatePage = lazyPage(() => import("../features/customfields/pages/CustomFieldCreatePage"));
const CustomFieldEditPage = lazyPage(() => import("../features/customfields/pages/CustomFieldEditPage"));
const BeneficiaryImportPage = lazyPage(() => import("../features/beneficiaries/pages/BeneficiaryImportPage"));
const EnterpriseListPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseListPage"));
const EnterpriseCreatePage = lazyPage(() => import("../features/enterprise/pages/EnterpriseCreatePage"));
const EnterpriseDetailsPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseDetailsPage"));
const EnterpriseEditPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseEditPage"));
const EnterpriseMemberListPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseMemberListPage"));
const EnterpriseMemberCreatePage = lazyPage(() => import("../features/enterprise/pages/EnterpriseMemberCreatePage"));
const EnterpriseMemberDetailsPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseMemberDetailsPage"));
const EnterpriseMemberEditPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseMemberEditPage"));
const ActivityListPage = lazyPage(() => import("../features/activities/pages/ActivityListPage"));
const ActivityCreatePage = lazyPage(() => import("../features/activities/pages/ActivityCreatePage"));
const ActivityDetailsPage = lazyPage(() => import("../features/activities/pages/ActivityDetailsPage"));
const ActivityEditPage = lazyPage(() => import("../features/activities/pages/ActivityEditPage"));
const AttendanceListPage = lazyPage(() => import("../features/attendance/pages/AttendanceListPage"));
const AttendanceCreatePage = lazyPage(() => import("../features/attendance/pages/AttendanceCreatePage"));
const AttendanceEditPage = lazyPage(() => import("../features/attendance/pages/AttendanceEditPage"));
const AttendanceSheetPage = lazyPage(() => import("../features/attendance/pages/AttendanceSheetPage"));
const LookupListPage = lazyPage(() => import("../features/lookups/pages/LookupListPage"));
const LookupCreatePage = lazyPage(() => import("../features/lookups/pages/LookupCreatePage"));
const LookupCategoryPage = lazyPage(() => import("../features/lookups/pages/LookupCategoryPage"));
const LookupEditPage = lazyPage(() => import("../features/lookups/pages/LookupEditPage"));
const DonorListPage = lazyPage(() => import("../features/donors/pages/DonorListPage"));
const DonorCreatePage = lazyPage(() => import("../features/donors/pages/DonorCreatePage"));
const DonorDetailsPage = lazyPage(() => import("../features/donors/pages/DonorDetailsPage"));
const DonorEditPage = lazyPage(() => import("../features/donors/pages/DonorEditPage"));
const DonationListPage = lazyPage(() => import("../features/donations/pages/DonationListPage"));
const DonationCreatePage = lazyPage(() => import("../features/donations/pages/DonationCreatePage"));
const DonationDetailsPage = lazyPage(() => import("../features/donations/pages/DonationDetailsPage"));
const DonationEditPage = lazyPage(() => import("../features/donations/pages/DonationEditPage"));
const DonationTracePage = lazyPage(() => import("../features/donations/pages/DonationTracePage"));
const UntracedSpendingPage = lazyPage(() => import("../features/donations/pages/UntracedSpendingPage"));
const DonorSharePage = lazyPage(() => import("../features/donations/pages/DonorSharePage"));
const ReportsPage = lazyPage(() => import("../features/reports/pages/ReportsPage"));
const ChangePasswordPage = lazyPage(() => import("../features/auth/pages/ChangePasswordPage"));
const SuperAdminDashboardPage = lazyPage(() => import("../features/superadmin/pages/SuperAdminDashboardPage"));
const OrganizationListPage = lazyPage(() => import("../features/superadmin/pages/OrganizationListPage"));
const OrganizationCreatePage = lazyPage(() => import("../features/superadmin/pages/OrganizationCreatePage"));
const OrganizationDetailsPage = lazyPage(() => import("../features/superadmin/pages/OrganizationDetailsPage"));
const OrganizationEditPage = lazyPage(() => import("../features/superadmin/pages/OrganizationEditPage"));
const PlanListPage = lazyPage(() => import("../features/superadmin/pages/PlanListPage"));
const SubscriptionManagementPage = lazyPage(() => import("../features/superadmin/pages/SubscriptionManagementPage"));
const ProgramListPage = lazyPage(() => import("../features/programs/pages/ProgramListPage"));
const ProgramCreatePage = lazyPage(() => import("../features/programs/pages/ProgramCreatePage"));
const ProgramDetailsPage = lazyPage(() => import("../features/programs/pages/ProgramDetailsPage"));
const ProgramEditPage = lazyPage(() => import("../features/programs/pages/ProgramEditPage"));
const BeneficiaryListPage = lazyPage(() => import("../features/beneficiaries/pages/BeneficiaryListPage"));
const BeneficiaryCreatePage = lazyPage(() => import("../features/beneficiaries/pages/BeneficiaryCreatePage"));
const BeneficiaryDetailsPage = lazyPage(() => import("../features/beneficiaries/pages/BeneficiaryDetailsPage"));
const BeneficiaryEditPage = lazyPage(() => import("../features/beneficiaries/pages/BeneficiaryEditPage"));
const ProjectListPage = lazyPage(() => import("../features/projects/pages/projectListPage"));
const ProjectCreatePage = lazyPage(() => import("../features/projects/pages/projectCreatePage"));
const ProjectDetailsPage = lazyPage(() => import("../features/projects/pages/projectDetailsPage"));
const ProjectEditPage = lazyPage(() => import("../features/projects/pages/projectEditPage"));
const ActivityRunListPage = lazyPage(() => import("../features/activityRuns/pages/ActivityRunListPage"));
const ActivityRunCreatePage = lazyPage(() => import("../features/activityRuns/pages/ActivityRunCreatePage"));
const ActivityRunDetailsPage = lazyPage(() => import("../features/activityRuns/pages/ActivityRunDetailsPage"));
const ActivityRunEditPage = lazyPage(() => import("../features/activityRuns/pages/ActivityRunEditPage"));
const TorListPage = lazyPage(() => import("../features/tor/pages/TorListPage"));
const TorCreatePage = lazyPage(() => import("../features/tor/pages/TorCreatePage"));
const TorDetailsPage = lazyPage(() => import("../features/tor/pages/TorDetailsPage"));
const TorEditPage = lazyPage(() => import("../features/tor/pages/TorEditPage"));
const EnrollmentListPage = lazyPage(() => import("../features/enrollments/pages/EnrollmentListPage"));
const EnrollmentCreatePage = lazyPage(() => import("../features/enrollments/pages/EnrollmentCreatePage"));
const EnrollmentDetailsPage = lazyPage(() => import("../features/enrollments/pages/EnrollmentDetailsPage"));
const EnrollmentEditPage = lazyPage(() => import("../features/enrollments/pages/EnrollmentEditPage"));
const ServiceDeliveryListPage = lazyPage(() => import("../features/ServiceDelivery/pages/ServiceDeliveryListPage"));
const ServiceDeliveryCreatePage = lazyPage(() => import("../features/ServiceDelivery/pages/ServiceDeliveryCreatePage"));
const ServiceDeliveryDetailsPage = lazyPage(() => import("../features/ServiceDelivery/pages/ServiceDeliveryDetailsPage"));
const ServiceDeliveryEditPage = lazyPage(() => import("../features/ServiceDelivery/pages/ServiceDeliveryEditPage"));
const UserListPage = lazyPage(() => import("../features/users/pages/UserListPage"));
const UserCreatePage = lazyPage(() => import("../features/users/pages/UserCreatePage"));
const UserEditPage = lazyPage(() => import("../features/users/pages/UserEditPage"));


const PageFallback = () => (
    <LoadingState message="Loading..." />
);


const AppRoutes = () => {

    return (

        <Suspense fallback={<PageFallback />}>

        <Routes>

            {/* ==================================================
                PUBLIC
            ================================================== */}

            <Route
                path="/login"
                element={
                    <LoginPage />
                }
            />

            {/* Donor share link: no login, read-only */}

            <Route
                path="/share/donor/:token"
                element={
                    <DonorSharePage />
                }
            />


            {/* ==================================================
                PROTECTED APPLICATION
            ================================================== */}

            <Route
                element={
                    <ProtectedRoute>
                        <DashboardLayout />
                    </ProtectedRoute>
                }
            >

                {/* ==================================================
                    DEFAULT
                ================================================== */}

                <Route
                    index
                    element={
                        <Navigate
                            to="/dashboard"
                            replace
                        />
                    }
                />


                {/* ==================================================
                    MY ACCOUNT
                ================================================== */}

                <Route
                    path="/account/password"
                    element={
                        <ChangePasswordPage />
                    }
                />


                {/* ==================================================
                    DASHBOARD
                ================================================== */}

                <Route
                    path="/dashboard"
                    element={
                        <DashboardPage />
                    }
                />


                {/* ==================================================
                    SUPER ADMIN
                ================================================== */}

                <Route
                    path="/superadmin"
                    element={
                        <SuperAdminRoute>
                            <SuperAdminDashboardPage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/organizations"
                    element={
                        <SuperAdminRoute>
                            <OrganizationListPage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/organizations/create"
                    element={
                        <SuperAdminRoute>
                            <OrganizationCreatePage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/organizations/:id"
                    element={
                        <SuperAdminRoute>
                            <OrganizationDetailsPage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/organizations/:id/edit"
                    element={
                        <SuperAdminRoute>
                            <OrganizationEditPage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/plans"
                    element={
                        <SuperAdminRoute>
                            <PlanListPage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/subscriptions"
                    element={
                        <SuperAdminRoute>
                            <SubscriptionManagementPage />
                        </SuperAdminRoute>
                    }
                />


                {/* ==================================================
                    ORGANIZATION SETTINGS
                ================================================== */}

                <Route
                    path="/settings/organization"
                    element={
                        <OrganizationSettingsPage />
                    }
                />


                {/* ==================================================
                    USERS
                ================================================== */}

                <Route
                    path="/users"
                    element={
                        <PermissionRoute
                            permission="user.read"
                        >
                            <UserListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/users/create"
                    element={
                        <PermissionRoute
                            permission="user.create"
                        >
                            <UserCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/users/:id/edit"
                    element={
                        <PermissionRoute
                            permission="user.update"
                        >
                            <UserEditPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    PROGRAMS
                ================================================== */}

                <Route
                    path="/programs"
                    element={
                        <ProgramListPage />
                    }
                />

                <Route
                    path="/programs/create"
                    element={
                        <ProgramCreatePage />
                    }
                />

                <Route
                    path="/programs/:id"
                    element={
                        <ProgramDetailsPage />
                    }
                />

                <Route
                    path="/programs/:id/edit"
                    element={
                        <ProgramEditPage />
                    }
                />


                {/* ==================================================
                    BENEFICIARIES
                ================================================== */}

                <Route
                    path="/beneficiaries"
                    element={
                        <BeneficiaryListPage />
                    }
                />

                <Route
                    path="/beneficiaries/create"
                    element={
                        <BeneficiaryCreatePage />
                    }
                />

                <Route
                    path="/beneficiaries/:id"
                    element={
                        <BeneficiaryDetailsPage />
                    }
                />

                <Route
                    path="/beneficiaries/:id/edit"
                    element={
                        <BeneficiaryEditPage />
                    }
                />

                <Route
                    path="/beneficiaries/import"
                    element={
                        <BeneficiaryImportPage />
                    }
                />


{/* ==================================================
    ENTERPRISES
================================================== */}

<Route
    path="/enterprises"
    element={
        <EnterpriseListPage />
    }
/>


<Route
    path="/enterprises/create"
    element={
        <EnterpriseCreatePage />
    }
/>


<Route
    path="/enterprises/:id"
    element={
        <EnterpriseDetailsPage />
    }
/>


<Route
    path="/enterprises/:id/edit"
    element={
        <EnterpriseEditPage />
    }
/>


{/* ==================================================
    ENTERPRISE MEMBERS
================================================== */}

<Route
    path="/enterprise-members"
    element={
        <EnterpriseMemberListPage />
    }
/>


<Route
    path="/enterprise-members/:id"
    element={
        <EnterpriseMemberDetailsPage />
    }
/>


<Route
    path="/enterprise-members/:id/edit"
    element={
        <EnterpriseMemberEditPage />
    }
/>


{/* ==================================================
    ENTERPRISE MEMBERS BY ENTERPRISE
================================================== */}

<Route
    path="/enterprises/:enterpriseId/members"
    element={
        <EnterpriseMemberListPage />
    }
/>


<Route
    path="/enterprises/:enterpriseId/members/create"
    element={
        <EnterpriseMemberCreatePage />
    }
/>


<Route
    path="/enterprises/:enterpriseId/members/:memberId"
    element={
        <EnterpriseMemberDetailsPage />
    }
/>


<Route
    path="/enterprises/:enterpriseId/members/:memberId/edit"
    element={
        <EnterpriseMemberEditPage />
    }
/>

                {/* ==================================================
                    ENROLLMENTS
                ================================================== */}

                <Route
                    path="/enrollments"
                    element={
                        <EnrollmentListPage />
                    }
                />

                <Route
                    path="/enrollments/create"
                    element={
                        <EnrollmentCreatePage />
                    }
                />

                <Route
                    path="/enrollments/:id"
                    element={
                        <EnrollmentDetailsPage />
                    }
                />

                <Route
                    path="/enrollments/:id/edit"
                    element={
                        <EnrollmentEditPage />
                    }
                />


                {/* ==================================================
                    PROJECTS
                ================================================== */}

                <Route
                    path="/projects"
                    element={
                        <ProjectListPage />
                    }
                />

                <Route
                    path="/projects/create"
                    element={
                        <ProjectCreatePage />
                    }
                />

                <Route
                    path="/projects/:id"
                    element={
                        <ProjectDetailsPage />
                    }
                />

                <Route
                    path="/projects/:id/edit"
                    element={
                        <ProjectEditPage />
                    }
                />


                {/* ==================================================
                    ACTIVITIES
                ================================================== */}

                <Route
                    path="/activities"
                    element={
                        <ActivityListPage />
                    }
                />

                <Route
                    path="/activities/create"
                    element={
                        <ActivityCreatePage />
                    }
                />

                <Route
                    path="/activities/:id"
                    element={
                        <ActivityDetailsPage />
                    }
                />

                <Route
                    path="/activities/:id/edit"
                    element={
                        <ActivityEditPage />
                    }
                />


                {/* ==================================================
                    ACTIVITY RUNS
                ================================================== */}

                <Route
                    path="/activity-runs"
                    element={
                        <ActivityRunListPage />
                    }
                />

                <Route
                    path="/activity-runs/create"
                    element={
                        <ActivityRunCreatePage />
                    }
                />

                <Route
                    path="/activity-runs/:id"
                    element={
                        <ActivityRunDetailsPage />
                    }
                />

                <Route
                    path="/activity-runs/:id/edit"
                    element={
                        <ActivityRunEditPage />
                    }
                />


                {/* ==================================================
                    TERMS OF REFERENCE
                ================================================== */}

                <Route
                    path="/tors"
                    element={
                        <PermissionRoute
                            permission="tor.read"
                        >
                            <TorListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/tors/create"
                    element={
                        <PermissionRoute
                            permission="tor.create"
                        >
                            <TorCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/tors/:id"
                    element={
                        <PermissionRoute
                            permission="tor.read"
                        >
                            <TorDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/tors/:id/edit"
                    element={
                        <PermissionRoute
                            permission="tor.update"
                        >
                            <TorEditPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    ATTENDANCE
                ================================================== */}

                <Route
                    path="/attendance"
                    element={
                        <AttendanceListPage />
                    }
                />

                <Route
                    path="/attendance/create"
                    element={
                        <AttendanceCreatePage />
                    }
                />

                <Route
                    path="/attendance/:id/edit"
                    element={
                        <AttendanceEditPage />
                    }
                />

                <Route
                    path="/attendance/:id/sheet"
                    element={
                        <AttendanceSheetPage />
                    }
                />


                {/* ==================================================
                    SERVICE DELIVERY
                ================================================== */}

                <Route
                    path="/service-deliveries"
                    element={
                        <ServiceDeliveryListPage />
                    }
                />

                <Route
                    path="/service-deliveries/create"
                    element={
                        <ServiceDeliveryCreatePage />
                    }
                />

                <Route
                    path="/service-deliveries/:id"
                    element={
                        <ServiceDeliveryDetailsPage />
                    }
                />

                <Route
                    path="/service-deliveries/:id/edit"
                    element={
                        <ServiceDeliveryEditPage />
                    }
                />


                {/* ==================================================
                    CUSTOM FIELDS
                ================================================== */}

                <Route
                    path="/settings/custom-fields"
                    element={
                        <PermissionRoute
                            permission="customfield.read"
                        >
                            <CustomFieldListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/settings/custom-fields/create"
                    element={
                        <PermissionRoute
                            permission="customfield.create"
                        >
                            <CustomFieldCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/settings/custom-fields/:id/edit"
                    element={
                        <PermissionRoute
                            permission="customfield.update"
                        >
                            <CustomFieldEditPage />
                        </PermissionRoute>
                    }
                />


{/* ==================================================
    LOOKUPS
================================================== */}

<Route
    path="/lookups"
    element={
        <LookupListPage />
    }
/>

<Route
    path="/lookups/create"
    element={
        <LookupCreatePage />
    }
/>

<Route
    path="/lookups/module/:module/category/:category"
    element={
        <LookupCategoryPage />
    }
/>

<Route
    path="/lookups/:id/edit"
    element={
        <LookupEditPage />
    }
/>


                {/* ==================================================
                    DONORS
                ================================================== */}

                <Route
                    path="/donors"
                    element={
                        <DonorListPage />
                    }
                />

                <Route
                    path="/donors/create"
                    element={
                        <DonorCreatePage />
                    }
                />

                <Route
                    path="/donors/:id"
                    element={
                        <DonorDetailsPage />
                    }
                />

                <Route
                    path="/donors/:id/edit"
                    element={
                        <DonorEditPage />
                    }
                />


                {/* ==================================================
                    DONATIONS
                ================================================== */}

                <Route
                    path="/donations"
                    element={
                        <DonationListPage />
                    }
                />

                <Route
                    path="/donations/create"
                    element={
                        <DonationCreatePage />
                    }
                />

                <Route
                    path="/donations/untraced"
                    element={
                        <UntracedSpendingPage />
                    }
                />

                <Route
                    path="/donations/:id"
                    element={
                        <DonationDetailsPage />
                    }
                />

                <Route
                    path="/donations/:id/trace"
                    element={
                        <DonationTracePage />
                    }
                />

                                <Route
                    path="/donations/:id/edit"
                    element={
                        <DonationEditPage />
                    }
                />


                {/* ==================================================
                    REPORTS
                ================================================== */}

                <Route
                    path="/reports"
                    element={
                        <ReportsPage />
                    }
                />

            </Route>

            {/* ==================================================
                FALLBACK
            ================================================== */}

            <Route
                path="*"
                element={
                    <Navigate
                        to="/dashboard"
                        replace
                    />
                }
            />

        </Routes>

        </Suspense>

    );

};


export default AppRoutes;