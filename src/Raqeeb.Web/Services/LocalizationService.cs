namespace Raqeeb.Web.Services;

/// <summary>
/// Localization service interface for accessing localized strings.
/// </summary>
public interface ILocalizationService
{
    string this[string key] { get; }
    string this[string key, params object[] args] { get; }
    string CurrentLanguage { get; }
    bool IsRtl { get; }
    void SetLanguage(string language);
}

/// <summary>
/// Simple English-only localization service.
/// Arabic and other languages will be added in Phase 5.
/// </summary>
public class LocalizationService : ILocalizationService
{
    private static readonly Dictionary<string, string> Translations = new()
    {
        // App-wide
        ["AppName"] = "Raqeeb",
        ["AppTitle"] = "Raqeeb Vulnerability Scanner",
        ["SystemOnline"] = "System Online",
        ["Copyright"] = "© {0} Raqeeb. Built for security.",
        ["ErrorOccurred"] = "An unhandled error has occurred.",
        ["Reload"] = "Reload",
        ["Loading"] = "Loading...",
        ["Save"] = "Save",
        ["Cancel"] = "Cancel",
        ["Delete"] = "Delete",
        ["Edit"] = "Edit",
        ["Add"] = "Add",
        ["Search"] = "Search",
        ["Filter"] = "Filter",
        ["Actions"] = "Actions",
        ["Status"] = "Status",
        ["Details"] = "Details",
        ["View"] = "View",
        ["Close"] = "Close",
        ["Confirm"] = "Confirm",
        ["Yes"] = "Yes",
        ["No"] = "No",
        ["All"] = "All",
        ["None"] = "None",
        
        // Navigation
        ["NavMain"] = "MAIN",
        ["NavDashboard"] = "Dashboard",
        ["NavTargets"] = "Targets",
        ["NavScanProfiles"] = "Scan Profiles",
        ["NavScanning"] = "SCANNING",
        ["NavNewScan"] = "New Scan",
        ["NavScanHistory"] = "Scan History",
        ["NavSystem"] = "SYSTEM",
        ["NavSettings"] = "Settings",
        
        // Dashboard
        ["DashboardTitle"] = "Dashboard",
        ["DashboardWelcome"] = "Welcome to Raqeeb",
        ["TotalScans"] = "Total Scans",
        ["ActiveScans"] = "Active Scans",
        ["TotalVulnerabilities"] = "Total Vulnerabilities",
        ["CriticalVulnerabilities"] = "Critical Issues",
        ["RecentScans"] = "Recent Scans",
        ["VulnerabilityBreakdown"] = "Vulnerability Breakdown",
        ["QuickActions"] = "Quick Actions",
        ["StartNewScan"] = "Start New Scan",
        ["ViewAllScans"] = "View All Scans",
        ["NoScansYet"] = "No scans yet",
        ["StartFirstScan"] = "Start your first scan to see results here.",
        
        // Severity
        ["Critical"] = "Critical",
        ["High"] = "High",
        ["Medium"] = "Medium",
        ["Low"] = "Low",
        ["Info"] = "Info",
        
        // Scan Status
        ["Queued"] = "Queued",
        ["Running"] = "Running",
        ["Completed"] = "Completed",
        ["Failed"] = "Failed",
        ["Cancelled"] = "Cancelled",
        
        // Targets
        ["TargetsTitle"] = "Targets",
        ["AddTarget"] = "Add Target",
        ["TargetUrl"] = "Target URL",
        ["TargetCreated"] = "Created",
        ["TargetVerified"] = "Verified",
        ["NoTargets"] = "No targets configured",
        ["AddFirstTarget"] = "Add your first target to start scanning.",
        
        // Scan Profiles
        ["ScanProfilesTitle"] = "Scan Profiles",
        ["CreateProfile"] = "Create Profile",
        ["ProfileName"] = "Profile Name",
        ["ProfileDescription"] = "Description",
        ["DefaultProfile"] = "Default",
        ["NoProfiles"] = "No scan profiles",
        
        // New Scan
        ["NewScanTitle"] = "New Scan",
        ["SelectTarget"] = "Select Target",
        ["SelectProfile"] = "Select Profile",
        ["StartScan"] = "Start Scan",
        ["ScanOptions"] = "Scan Options",
        
        // Scan History
        ["ScanHistoryTitle"] = "Scan History",
        ["ScanId"] = "Scan ID",
        ["Target"] = "Target",
        ["Profile"] = "Profile",
        ["StartTime"] = "Start Time",
        ["EndTime"] = "End Time",
        ["Duration"] = "Duration",
        ["Findings"] = "Findings",
        ["NoScanHistory"] = "No scan history",
        
        // Scan Details
        ["ScanDetailsTitle"] = "Scan Details",
        ["ScanInformation"] = "Scan Information",
        ["Summary"] = "Summary",
        ["TotalFindings"] = "Total Findings",
        ["VulnerabilitiesFound"] = "Vulnerabilities Found",
        ["ScanningInProgress"] = "Scanning in progress...",
        ["CancelScan"] = "Cancel Scan",
        ["ExportReport"] = "Export Report",
        ["DownloadHtml"] = "Download HTML",
        ["DownloadJson"] = "Download JSON",
        ["ViewInBrowser"] = "View in Browser",
        ["InProgress"] = "In progress...",
        ["LiveUpdating"] = "Live updating...",
        
        // Vulnerabilities
        ["VulnerabilityName"] = "Vulnerability",
        ["VulnerabilitySeverity"] = "Severity",
        ["VulnerabilityUrl"] = "Affected URL",
        ["VulnerabilityEvidence"] = "Evidence",
        ["VulnerabilityRemediation"] = "Remediation",
        ["NoVulnerabilities"] = "No vulnerabilities found",
        
        // Settings
        ["SettingsTitle"] = "Settings",
        ["Appearance"] = "Appearance",
        ["Theme"] = "Theme",
        ["ThemeDescription"] = "Choose between light and dark mode",
        ["LightMode"] = "Light",
        ["DarkMode"] = "Dark",
        ["Language"] = "Language",
        ["LanguageDescription"] = "Select your preferred language",
        ["Notifications"] = "Notifications",
        ["ScanAlerts"] = "Scan Completion Alerts",
        ["ScanAlertsDescription"] = "Get notified when scans complete",
        ["CriticalAlerts"] = "Critical Vulnerability Alerts",
        ["CriticalAlertsDescription"] = "Alert on critical findings",
        ["About"] = "About",
        ["Version"] = "Version",
        ["Build"] = "Build",
        ["License"] = "License",
        ["VulnerabilityScanner"] = "Vulnerability Scanner",
        ["Security"] = "Security",
        ["ApiAccess"] = "API Access",
        ["ApiAccessDescription"] = "Manage API tokens for automation",
        ["ManageKeys"] = "Manage Keys",
        
        // Time
        ["JustNow"] = "Just now",
        ["MinutesAgo"] = "{0} minutes ago",
        ["HoursAgo"] = "{0} hours ago",
        ["DaysAgo"] = "{0} days ago",
        ["Today"] = "Today",
        ["Yesterday"] = "Yesterday",
    };

    public string CurrentLanguage => "en";
    
    public bool IsRtl => false;

    public string this[string key] => Translations.TryGetValue(key, out var value) ? value : key;

    public string this[string key, params object[] args]
    {
        get
        {
            var value = this[key];
            return args.Length > 0 ? string.Format(value, args) : value;
        }
    }

    public void SetLanguage(string language)
    {
        // Language switching disabled for now - will be implemented in Phase 5
    }
}
