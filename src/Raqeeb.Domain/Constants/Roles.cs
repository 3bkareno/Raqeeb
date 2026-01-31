namespace Raqeeb.Domain.Constants;

/// <summary>
/// Application role constants.
/// </summary>
public static class Roles
{
    /// <summary>
    /// Administrator role with full access.
    /// </summary>
    public const string Admin = "Admin";

    /// <summary>
    /// Standard user role with normal access.
    /// </summary>
    public const string User = "User";

    /// <summary>
    /// Viewer role with read-only access.
    /// </summary>
    public const string Viewer = "Viewer";

    /// <summary>
    /// Get all role names.
    /// </summary>
    public static readonly string[] All = [Admin, User, Viewer];
}

/// <summary>
/// Application permission constants.
/// </summary>
public static class Permissions
{
    // Target permissions
    public const string TargetsView = "Targets.View";
    public const string TargetsCreate = "Targets.Create";
    public const string TargetsEdit = "Targets.Edit";
    public const string TargetsDelete = "Targets.Delete";

    // Scan permissions
    public const string ScansView = "Scans.View";
    public const string ScansCreate = "Scans.Create";
    public const string ScansCancel = "Scans.Cancel";
    public const string ScansDelete = "Scans.Delete";

    // Profile permissions
    public const string ProfilesView = "Profiles.View";
    public const string ProfilesCreate = "Profiles.Create";
    public const string ProfilesEdit = "Profiles.Edit";
    public const string ProfilesDelete = "Profiles.Delete";

    // Report permissions
    public const string ReportsView = "Reports.View";
    public const string ReportsExport = "Reports.Export";

    // Settings permissions
    public const string SettingsView = "Settings.View";
    public const string SettingsEdit = "Settings.Edit";

    // Admin permissions
    public const string UsersView = "Users.View";
    public const string UsersCreate = "Users.Create";
    public const string UsersEdit = "Users.Edit";
    public const string UsersDelete = "Users.Delete";
    public const string RolesManage = "Roles.Manage";

    /// <summary>
    /// Get permissions for Admin role.
    /// </summary>
    public static readonly string[] AdminPermissions =
    [
        TargetsView, TargetsCreate, TargetsEdit, TargetsDelete,
        ScansView, ScansCreate, ScansCancel, ScansDelete,
        ProfilesView, ProfilesCreate, ProfilesEdit, ProfilesDelete,
        ReportsView, ReportsExport,
        SettingsView, SettingsEdit,
        UsersView, UsersCreate, UsersEdit, UsersDelete, RolesManage
    ];

    /// <summary>
    /// Get permissions for User role.
    /// </summary>
    public static readonly string[] UserPermissions =
    [
        TargetsView, TargetsCreate, TargetsEdit, TargetsDelete,
        ScansView, ScansCreate, ScansCancel,
        ProfilesView, ProfilesCreate, ProfilesEdit,
        ReportsView, ReportsExport,
        SettingsView
    ];

    /// <summary>
    /// Get permissions for Viewer role.
    /// </summary>
    public static readonly string[] ViewerPermissions =
    [
        TargetsView,
        ScansView,
        ProfilesView,
        ReportsView,
        SettingsView
    ];
}
