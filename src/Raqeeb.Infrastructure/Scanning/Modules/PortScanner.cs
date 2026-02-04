using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules
{
    public class PortScanner : IScannerModule
    {
        public string Name => "PortScanner";
        public string Description => "Scans for open ports on the target host to identify exposed services.";

        // Common ports to scan
        private static readonly List<int> CommonPorts = new()
        {
            21,   // FTP
            22,   // SSH
            23,   // Telnet
            25,   // SMTP
            80,   // HTTP
            110,  // POP3
            143,  // IMAP
            443,  // HTTPS
            445,  // SMB
            3306, // MySQL
            3389, // RDP
            5432, // PostgreSQL
            5900, // VNC
            6379, // Redis
            8080, // HTTP Alt
            8443, // HTTPS Alt
            27017 // MongoDB
        };

        private static readonly Dictionary<int, string> PortServices = new()
        {
            { 21, "FTP" },
            { 22, "SSH" },
            { 23, "Telnet" },
            { 25, "SMTP" },
            { 80, "HTTP" },
            { 110, "POP3" },
            { 143, "IMAP" },
            { 443, "HTTPS" },
            { 445, "SMB" },
            { 3306, "MySQL" },
            { 3389, "RDP" },
            { 5432, "PostgreSQL" },
            { 5900, "VNC" },
            { 6379, "Redis" },
            { 8080, "HTTP Alternate" },
            { 8443, "HTTPS Alternate" },
            { 27017, "MongoDB" }
        };

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                var uri = new Uri(context.Target.Url);
                var host = uri.Host;

                // Resolve hostname to IP
                IPAddress? ipAddress = null;
                try
                {
                    var addresses = await Dns.GetHostAddressesAsync(host);
                    if (addresses.Length > 0)
                    {
                        ipAddress = addresses[0];
                    }
                }
                catch
                {
                    // Could not resolve, try using host directly
                }

                if (ipAddress == null && !IPAddress.TryParse(host, out ipAddress))
                {
                    return vulnerabilities;
                }

                // Scan common ports
                foreach (var port in CommonPorts.Take(10)) // Limit number of ports for safety
                {
                    var isOpen = await IsPortOpenAsync(ipAddress.ToString(), port);
                    if (isOpen)
                    {
                        var serviceName = PortServices.ContainsKey(port) ? PortServices[port] : "Unknown";
                        var severity = DeterminePortSeverity(port);

                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = $"Open Port {port}",
                            Description = $"Port {port} ({serviceName}) is open on the target host. This may expose unnecessary services to potential attackers.",
                            Severity = severity,
                            Evidence = $"Host: {host}\nIP: {ipAddress}\nPort: {port}\nService: {serviceName}",
                            Remediation = GetPortRemediation(port, serviceName),
                            Url = context.Target.Url
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Port Scanner error: {ex.Message}");
            }

            return vulnerabilities;
        }

        private async Task<bool> IsPortOpenAsync(string host, int port)
        {
            try
            {
                using var tcpClient = new TcpClient();
                var connectTask = tcpClient.ConnectAsync(host, port);
                var timeoutTask = Task.Delay(2000); // 2 second timeout

                var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                
                if (completedTask == connectTask && !connectTask.IsFaulted)
                {
                    return tcpClient.Connected;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private Severity DeterminePortSeverity(int port)
        {
            // Critical - Insecure protocols or databases exposed
            if (port == 23 || // Telnet
                port == 3306 || // MySQL
                port == 5432 || // PostgreSQL
                port == 6379 || // Redis
                port == 27017) // MongoDB
            {
                return Severity.High;
            }

            // Medium - Remote access or file services
            if (port == 21 || // FTP
                port == 3389 || // RDP
                port == 5900 || // VNC
                port == 445) // SMB
            {
                return Severity.Medium;
            }

            // Low - Standard web services (expected)
            if (port == 80 || port == 443 || port == 8080 || port == 8443)
            {
                return Severity.Info;
            }

            return Severity.Low;
        }

        private string GetPortRemediation(int port, string serviceName)
        {
            return port switch
            {
                23 => "Telnet is insecure. Replace with SSH (port 22) for encrypted remote access.",
                21 => "FTP transmits credentials in plain text. Use SFTP or FTPS instead. Close if not needed.",
                3306 => "MySQL should not be exposed to the internet. Use firewall rules to restrict access to trusted IPs only.",
                5432 => "PostgreSQL should not be exposed to the internet. Use firewall rules to restrict access to trusted IPs only.",
                6379 => "Redis should not be exposed to the internet. Configure authentication and use firewall rules.",
                27017 => "MongoDB should not be exposed to the internet. Enable authentication and restrict access.",
                3389 => "RDP should not be exposed to the internet. Use VPN for remote access.",
                5900 => "VNC should not be exposed to the internet. Use VPN or SSH tunneling.",
                445 => "SMB should not be exposed to the internet. Use firewall rules to block external access.",
                _ => $"Review if {serviceName} needs to be exposed. Close port if service is not required. Use firewall rules to restrict access."
            };
        }
    }
}
