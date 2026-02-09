namespace Raqeeb.Domain.Constants;

/// <summary>
/// Maps vulnerability types to OWASP Top 10 2021 and CWE identifiers.
/// </summary>
public static class ComplianceMapping
{
    /// <summary>
    /// OWASP Top 10 2021 categories.
    /// </summary>
    public static class Owasp2021
    {
        public const string A01_BrokenAccessControl = "A01:2021 - Broken Access Control";
        public const string A02_CryptographicFailures = "A02:2021 - Cryptographic Failures";
        public const string A03_Injection = "A03:2021 - Injection";
        public const string A04_InsecureDesign = "A04:2021 - Insecure Design";
        public const string A05_SecurityMisconfiguration = "A05:2021 - Security Misconfiguration";
        public const string A06_VulnerableComponents = "A06:2021 - Vulnerable and Outdated Components";
        public const string A07_IdentificationFailures = "A07:2021 - Identification and Authentication Failures";
        public const string A08_SoftwareDataIntegrityFailures = "A08:2021 - Software and Data Integrity Failures";
        public const string A09_SecurityLoggingFailures = "A09:2021 - Security Logging and Monitoring Failures";
        public const string A10_ServerSideRequestForgery = "A10:2021 - Server-Side Request Forgery (SSRF)";
    }

    /// <summary>
    /// Common Weakness Enumeration (CWE) identifiers.
    /// </summary>
    public static class Cwe
    {
        // Injection
        public const string CWE_79_CrossSiteScripting = "CWE-79";
        public const string CWE_89_SqlInjection = "CWE-89";
        public const string CWE_77_CommandInjection = "CWE-77";
        public const string CWE_78_OSCommandInjection = "CWE-78";
        
        // Security Misconfiguration
        public const string CWE_16_Configuration = "CWE-16";
        public const string CWE_213_ExposureSensitiveInfo = "CWE-213";
        public const string CWE_693_ProtectionMechanism = "CWE-693";
        
        // CSRF
        public const string CWE_352_CSRF = "CWE-352";
        
        // Cryptographic Issues
        public const string CWE_295_CertificateValidation = "CWE-295";
        public const string CWE_326_WeakEncryption = "CWE-326";
        public const string CWE_327_WeakCrypto = "CWE-327";
        
        // CORS
        public const string CWE_942_PermissiveCORS = "CWE-942";
        
        // Open Redirect
        public const string CWE_601_OpenRedirect = "CWE-601";
        
        // Clickjacking
        public const string CWE_1021_Clickjacking = "CWE-1021";
        
        // Information Disclosure
        public const string CWE_200_InformationExposure = "CWE-200";
        public const string CWE_538_FilePathTraversal = "CWE-538";
        
        // Missing Security Headers
        public const string CWE_1004_SensitiveCookie = "CWE-1004";
        public const string CWE_693_MissingSecurityHeaders = "CWE-693";
    }

    /// <summary>
    /// Gets OWASP category for a vulnerability type.
    /// </summary>
    public static string? GetOwaspCategory(string vulnerabilityName)
    {
        return vulnerabilityName.ToLowerInvariant() switch
        {
            var name when name.Contains("xss") || name.Contains("cross-site scripting") 
                => Owasp2021.A03_Injection,
            var name when name.Contains("sql injection") || name.Contains("sqli") 
                => Owasp2021.A03_Injection,
            var name when name.Contains("command injection") 
                => Owasp2021.A03_Injection,
            var name when name.Contains("csrf") || name.Contains("cross-site request forgery") 
                => Owasp2021.A01_BrokenAccessControl,
            var name when name.Contains("ssl") || name.Contains("tls") || name.Contains("certificate") 
                => Owasp2021.A02_CryptographicFailures,
            var name when name.Contains("cors") 
                => Owasp2021.A05_SecurityMisconfiguration,
            var name when name.Contains("redirect") 
                => Owasp2021.A01_BrokenAccessControl,
            var name when name.Contains("clickjacking") || name.Contains("x-frame-options") 
                => Owasp2021.A05_SecurityMisconfiguration,
            var name when name.Contains("header") || name.Contains("security header") 
                => Owasp2021.A05_SecurityMisconfiguration,
            var name when name.Contains("directory") || name.Contains("path traversal") 
                => Owasp2021.A01_BrokenAccessControl,
            _ => null
        };
    }

    /// <summary>
    /// Gets CWE identifier for a vulnerability type.
    /// </summary>
    public static string? GetCweId(string vulnerabilityName)
    {
        return vulnerabilityName.ToLowerInvariant() switch
        {
            var name when name.Contains("xss") || name.Contains("cross-site scripting") 
                => Cwe.CWE_79_CrossSiteScripting,
            var name when name.Contains("sql injection") || name.Contains("sqli") 
                => Cwe.CWE_89_SqlInjection,
            var name when name.Contains("command injection") && name.Contains("os") 
                => Cwe.CWE_78_OSCommandInjection,
            var name when name.Contains("command injection") 
                => Cwe.CWE_77_CommandInjection,
            var name when name.Contains("csrf") || name.Contains("cross-site request forgery") 
                => Cwe.CWE_352_CSRF,
            var name when name.Contains("certificate") 
                => Cwe.CWE_295_CertificateValidation,
            var name when name.Contains("weak encryption") || name.Contains("weak cipher") 
                => Cwe.CWE_326_WeakEncryption,
            var name when name.Contains("ssl") || name.Contains("tls") 
                => Cwe.CWE_327_WeakCrypto,
            var name when name.Contains("cors") 
                => Cwe.CWE_942_PermissiveCORS,
            var name when name.Contains("redirect") 
                => Cwe.CWE_601_OpenRedirect,
            var name when name.Contains("clickjacking") || name.Contains("x-frame-options") 
                => Cwe.CWE_1021_Clickjacking,
            var name when name.Contains("directory") || name.Contains("path") 
                => Cwe.CWE_538_FilePathTraversal,
            var name when name.Contains("information disclosure") || name.Contains("information exposure") 
                => Cwe.CWE_200_InformationExposure,
            var name when name.Contains("cookie") && name.Contains("secure") 
                => Cwe.CWE_1004_SensitiveCookie,
            var name when name.Contains("header") || name.Contains("security header") 
                => Cwe.CWE_693_MissingSecurityHeaders,
            _ => null
        };
    }
}
