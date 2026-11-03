using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Threading;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace _292VPN_WPF;

public class ApiService
{
    // Canonical bootstrap endpoint for fresh installs and older configs.
    public const string DefaultManagedApiUrl = "https://103-253-23-106.sslip.io";
    private const string DefaultManagedApiHost = "103-253-23-106.sslip.io";
    private const string ConfigMutexName = "Global\\292VPN_Config_Mutex";
    private const long MaxSingBoxLogBytes = 10L * 1024 * 1024;
    private static readonly object _connectionLock = new();
    private static readonly object _singBoxLogLock = new();
    private static readonly SemaphoreSlim _nativeLifecycle = new(1, 1);
    private static readonly JsonSerializerOptions ConfigJsonOptions = new() { WriteIndented = true };
    private static readonly string[] UltraViewerProcessFamily =
    {
        "UltraViewer_Desktop.exe",
        "UltraViewer_Service.exe",
        "UltraViewer.exe",
        "uv_x64.exe",
        "uv_x86.exe"
    };

    // Other VPN clients must keep talking to their own servers directly. If our
    // TUN swallows their traffic they either fail outright or nest one tunnel
    // inside the other, which breaks both.
    private static readonly string[] OtherVpnProcessFamily =
    {
        "ProtonVPN.Client.exe",
        "ProtonVPNService.exe",
        "ProtonVPN.WireGuardService.exe",
        "nordvpn-service.exe",
        "NordVPN.exe",
        "nordvpnwg.exe",
        "wireguard.exe",
        "openvpn.exe",
        "openvpn-gui.exe",
        "tunnel.exe"
    };

    private const string VoiceProbeProcessName = "292VPN-VoiceProbe.exe";

    // These launchers assign a separate Vietnam HTTP/SOCKS proxy to each Zalo
    // profile. Sending either the launcher or its child through 292VPN nests
    // that proxy inside VLESS and can make the account proxy reject the session.
    private static readonly string[] ManagedZaloProcessFamily =
    {
        "ZaX.exe",
        "ZManager.exe",
        "Zalo.exe"
    };

    // Windows can identify UDP sockets by process name without resolving the
    // executable path. Keep common softphones on VLESS/XUDP in selected mode so
    // SIP signaling and RTP audio cannot fall through to the direct route.
    private static readonly string[] VoipProcessFamily =
    {
        "MicroSIP.exe",
        "microsip.exe",
        "Zoiper.exe",
        "zoiper.exe",
        "linphone.exe",
        "3CXPhone.exe",
        "3CXWin8Phone.exe",
        "Bria.exe",
        "PhonerLite.exe",
        "Jitsi.exe"
    };

    // Electron's NetworkService can lose process attribution after the traffic
    // enters the TUN. Keep Zalo's webview traffic on the proxy as a fallback.
    private static readonly string[] ZaloDomainSuffixes =
    {
        "zalo.me",
        "zaloapp.com",
        "zadn.vn",
        // Zalo Business traffic observed in sing-box logs also uses these domains.
        "zapps.vn",
        "zbox.vn"
    };

    // Microsoft Store WhatsApp runs as WhatsApp.Root.exe from a versioned
    // WindowsApps path. A user-entered "WhatsApp" or "WhatsApp.exe" therefore
    // matches neither sing-box's exact process_name nor its anchored path
    // regex, and call media falls through to direct-out.
    private static readonly string[] WhatsAppProcessFamily =
    {
        "WhatsApp.Root.exe",
        "WhatsApp.exe"
    };

    // WhatsApp Desktop renders through the shared msedgewebview2.exe. Its
    // installation directory is common to every WebView2 app, so it cannot be
    // attributed to WhatsApp by process path. Domain matching is the only
    // fallback that keeps that traffic on the proxy.
    private static readonly string[] WhatsAppDomainSuffixes =
    {
        "whatsapp.net",
        "whatsapp.com",
        "wa.me"
    };

    // sing-box matches process_name/process_path as exact strings, but Windows
    // executables are case-insensitive and ship mixed-case names ("MicroSIP.exe").
    // Enumerating lower/upper variants missed those, so match on the full path
    // with a case-insensitive regex instead.
    private static List<string> ProcessNameRegexes(IEnumerable<string> names)
    {
        var expanded = new HashSet<string>(StringComparer.Ordinal);
        foreach (string name in names.Where(n => !string.IsNullOrWhiteSpace(n)))
        {
            string fileName = Path.GetFileName(name.Trim());
            if (fileName.Length > 0)
            {
                expanded.Add($@"(?i)[\\/]{Regex.Escape(fileName)}$");
            }
        }

        return expanded.ToList();
    }

    private static List<string> ProcessPathRegexes(IEnumerable<string> paths)
    {
        var expanded = new HashSet<string>(StringComparer.Ordinal);
        foreach (string path in paths.Where(p => !string.IsNullOrWhiteSpace(p)))
        {
            expanded.Add($"(?i)^{Regex.Escape(path.Trim())}$");
        }

        return expanded.ToList();
    }

    private static List<string> ProcessDirectoryRegexes(IEnumerable<string> executablePaths)
    {
        var expanded = new HashSet<string>(StringComparer.Ordinal);
        foreach (string path in executablePaths.Where(p => !string.IsNullOrWhiteSpace(p)))
        {
            string? directory = Path.GetDirectoryName(path.Trim());
            if (!string.IsNullOrEmpty(directory) && !IsSharedExecutableDirectory(directory))
            {
                expanded.Add($@"(?i)^{Regex.Escape(directory.TrimEnd('\\', '/'))}[\\/].+\.exe$");
            }
        }

        return expanded.ToList();
    }

    private static bool IsSharedExecutableDirectory(string directory)
    {
        string normalized = Path.GetFullPath(directory).TrimEnd('\\', '/');
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\', '/');
        string system = Environment.GetFolderPath(Environment.SpecialFolder.System).TrimEnd('\\', '/');
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).TrimEnd('\\', '/');
        string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).TrimEnd('\\', '/');
        return normalized.Equals(windows, StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals(system, StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals(programFiles, StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals(programFilesX86, StringComparison.OrdinalIgnoreCase);
    }

    private static List<string> FindRunningProcessPaths(IEnumerable<string> processNames)
    {
        var names = new HashSet<string>(
            processNames.Select(Path.GetFileNameWithoutExtension).Where(name => !string.IsNullOrEmpty(name))!,
            StringComparer.OrdinalIgnoreCase);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Process process in Process.GetProcesses())
        {
            try
            {
                if (names.Contains(process.ProcessName) && TryGetProcessPath(process.Id, out string path))
                    paths.Add(Path.GetFullPath(path));
            }
            catch {}
            finally { process.Dispose(); }
        }
        return paths.ToList();
    }
    
    // Local static state to track connection details
    private static string _connectedState = "disconnected";
    private static DateTime? _connectionStartTime;
    private static string _currentPublicIp = "--";
    private static int _currentLatency;
    private static long _currentDownloadTotal;
    private static long _currentUploadTotal;
    private static Process? _singBoxProcess;
    private static Task? _connectionTask;

    private static CancellationTokenSource? _connectionCts;
    private static int _connectionGeneration;
    private static int _reconnectAttempt;
    private static int _reconnectDelay;
    private static string _lastError = string.Empty;

    // Bounded backoff after an unexpected sing-box exit, in seconds.
    private static readonly int[] ReconnectDelaysSeconds = { 1, 2, 5, 10, 20, 30 };
    private const int HealthFailureThreshold = 3;
    private static readonly TimeSpan HealthCheckInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(5);
    // Probe fixed IPs so tunnel readiness does not depend on the local
    // router's DNS, which can be unavailable while Windows updates routes.
    private static readonly string[] ProbeUrls = { "http://1.1.1.1/", "http://1.0.0.1/" };
    private static readonly string[] ProbeCidrs = { "1.1.1.1/32", "1.0.0.1/32" };
    private const int WireGuardStatusFailureThreshold = 3;
    private static readonly TimeSpan WireGuardHandshakeMaxAge = TimeSpan.FromSeconds(90);
    private static readonly int[] WireGuardRecoveryDelaysSeconds = { 2, 5, 10, 20, 30 };
    private static int _wireGuardStatusFailures;
    private static Task? _wireGuardRecoveryTask;
    private static CancellationTokenSource? _wireGuardMonitorCts;
    private static Task? _wireGuardMonitorTask;
    private static long _wireGuardLastReceived;
    private static long _wireGuardLastSent;
    private static bool _wireGuardTrafficSampled;
    
    // Clash API Client for fetching connection traffic
    private static readonly HttpClient _clashClient = new() { Timeout = TimeSpan.FromSeconds(2) };

    // sing-box exposes its Clash API on a fixed loopback port. Without a secret
    // any local process could read connection metadata or alter routing while we
    // run elevated, so every connection attempt rotates a fresh bearer token.
    private const string ClashApiHost = "127.0.0.1:9090";
    private static string _clashApiSecret = string.Empty;

    private static async Task<T?> GetFromClashApiAsync<T>(string path, CancellationToken cancellationToken = default)
    {
        using (var request = new HttpRequestMessage(HttpMethod.Get, $"http://{ClashApiHost}{path}"))
        {
            string secret = Volatile.Read(ref _clashApiSecret);
            if (!string.IsNullOrEmpty(secret))
            {
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", secret);
            }

            using (var response = await _clashClient.SendAsync(request, cancellationToken))
            {
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadFromJsonAsync<T>(cancellationToken: cancellationToken);
            }
        }
    }

    public class AppConfig
    {
        [JsonExtensionData]
        public Dictionary<string, JsonElement>? ExtensionData { get; set; }

        [JsonPropertyName("saved_proxies")]
        public List<Proxy> SavedProxies { get; set; } = new();

        [JsonPropertyName("active_proxy_id")]
        public string ActiveProxyId { get; set; } = string.Empty;

        [JsonPropertyName("local_port")]
        public int LocalPort { get; set; } = 10809;

        [JsonPropertyName("use_vpn_mode")]
        public bool UseVpnMode { get; set; } = true;

        [JsonPropertyName("start_on_boot")]
        public bool StartOnBoot { get; set; }

        [JsonPropertyName("auto_connect")]
        public bool AutoConnect { get; set; }

        [JsonPropertyName("auto_reconnect")]
        public bool AutoReconnect { get; set; }

        [JsonPropertyName("theme")]
        public string Theme { get; set; } = "light";

        [JsonPropertyName("proxy_mode")]
        public string ProxyMode { get; set; } = "selected_only";

        [JsonPropertyName("allowed_processes")]
        public List<string> AllowedProcesses { get; set; } = new() { "microsip.exe" };

        [JsonPropertyName("managed_api_url")]
        public string ManagedApiUrl { get; set; } = DefaultManagedApiUrl;

        [JsonPropertyName("managed_username")]
        public string ManagedUsername { get; set; } = string.Empty;

        [JsonPropertyName("managed_access_token")]
        public string ManagedAccessToken { get; set; } = string.Empty;

        [JsonPropertyName("managed_node_id")]
        public string ManagedNodeId { get; set; } = string.Empty;

        [JsonPropertyName("managed_device_id")]
        public string ManagedDeviceId { get; set; } = string.Empty;

        [JsonPropertyName("vpn_license_key")]
        public string VpnLicenseKey { get; set; } = string.Empty;

        // Opt-in escape hatch for machines whose GPU/composition stack kills the WPF
        // render thread (remote-control tools, flaky display drivers). Software
        // rendering costs CPU but removes UCEERR_RENDERTHREADFAILURE crashes.
        [JsonPropertyName("force_software_rendering")]
        public bool ForceSoftwareRendering { get; set; }
    }

    public class ProxyTestResult
    {
        public bool Success { get; set; }
        public int Latency { get; set; }
        public string Ip { get; set; } = "--";
        public string Message { get; set; } = "";
    }

    // WININET P/Invoke to reload system proxy settings instantly without restart
    [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder path, ref int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int size,
        bool order,
        int ipVersion,
        TcpTableClass tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr udpTable,
        ref int size,
        bool order,
        int ipVersion,
        UdpTableClass tableClass,
        uint reserved);

    private enum TcpTableClass
    {
        OwnerPidAll = 5
    }

    private enum UdpTableClass
    {
        OwnerPid = 1
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UdpRowOwnerPid
    {
        public uint LocalAddress;
        public uint LocalPort;
        public uint OwningPid;
    }

    public static void RefreshSystemProxySettings()
    {
        // INTERNET_OPTION_SETTINGS_CHANGED = 39
        // INTERNET_OPTION_REFRESH = 37
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
    }

    public static void SetSystemProxy(bool enable, string host = "127.0.0.1", int port = 10809)
    {
        try
        {
            using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
            {
                if (key != null)
                {
                    if (enable)
                    {
                        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                        key.SetValue("ProxyServer", $"{host}:{port}", RegistryValueKind.String);
                        key.SetValue("ProxyOverride", "<local>", RegistryValueKind.String);
                    }
                    else
                    {
                        key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                    }
                }
            }
            RefreshSystemProxySettings();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to set system proxy: {ex.Message}");
        }
    }

    private static bool CheckAdminStatus()
    {
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static T WithConfigMutex<T>(Func<T> action)
    {
        using (var mutex = new Mutex(false, ConfigMutexName))
        {
            bool acquired = false;
            try
            {
                try { acquired = mutex.WaitOne(TimeSpan.FromSeconds(10)); }
                catch (AbandonedMutexException) { acquired = true; }
                if (!acquired) throw new TimeoutException("Timed out waiting for the configuration lock.");
                AppPaths.EnsureDirectoriesAndMigrateLegacyConfig();
                return action();
            }
            finally
            {
                if (acquired) mutex.ReleaseMutex();
            }
        }
    }

    private static AppConfig ReadConfigUnsafe()
    {
        return ReadConfigFileUnsafe(AppPaths.ConfigFile);
    }

    private static AppConfig ReadConfigFileUnsafe(string configFile)
    {
        if (!File.Exists(configFile))
            return new AppConfig { ManagedApiUrl = DefaultManagedApiUrl };
        string jsonText = File.ReadAllText(configFile);
        var config = JsonSerializer.Deserialize<AppConfig>(jsonText) ?? new AppConfig();
        if (string.IsNullOrWhiteSpace(config.ManagedApiUrl))
            config.ManagedApiUrl = DefaultManagedApiUrl;
        config.ManagedAccessToken = UnprotectManagedToken(config.ManagedAccessToken);
        config.VpnLicenseKey = UnprotectManagedToken(config.VpnLicenseKey);
        foreach (Proxy proxy in config.SavedProxies)
        {
            proxy.User = UnprotectManagedToken(proxy.User);
            proxy.Pass = UnprotectManagedToken(proxy.Pass);
        }
        return config;
    }

    private static void WriteConfigUnsafe(AppConfig config)
    {
        string tempPath = AppPaths.ConfigFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            string managedAccessToken = config.ManagedAccessToken;
            string vpnLicenseKey = config.VpnLicenseKey;
            var proxySecrets = config.SavedProxies
                .Select(proxy => (proxy, proxy.User, proxy.Pass))
                .ToArray();
            config.ManagedAccessToken = ProtectManagedToken(managedAccessToken);
            config.VpnLicenseKey = ProtectManagedToken(vpnLicenseKey);
            foreach (var secret in proxySecrets)
            {
                secret.proxy.User = ProtectManagedToken(secret.User);
                secret.proxy.Pass = ProtectManagedToken(secret.Pass);
            }
            File.WriteAllText(tempPath, JsonSerializer.Serialize(config, ConfigJsonOptions), new UTF8Encoding(false));
            config.ManagedAccessToken = managedAccessToken;
            config.VpnLicenseKey = vpnLicenseKey;
            foreach (var secret in proxySecrets)
            {
                secret.proxy.User = secret.User;
                secret.proxy.Pass = secret.Pass;
            }
            if (File.Exists(AppPaths.ConfigFile))
            {
                string backupPath = AppPaths.ConfigFile + ".bak";
                File.Replace(tempPath, AppPaths.ConfigFile, backupPath, true);
                // Keep the last known-good configuration for recovery after an interrupted write.
                // It is replaced atomically on the next successful write.
            }
            else
            {
                File.Move(tempPath, AppPaths.ConfigFile);
            }
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    private AppConfig LoadConfig()
    {
        try
        {
            return WithConfigMutex(() =>
            {
                try
                {
                    return ReadConfigUnsafe();
                }
                catch (Exception primaryError) when (File.Exists(AppPaths.ConfigFile + ".bak"))
                {
                    string backupPath = AppPaths.ConfigFile + ".bak";
                    try
                    {
                        AppConfig backup = ReadConfigFileUnsafe(backupPath);
                        File.Copy(backupPath, AppPaths.ConfigFile, true);
                        Debug.WriteLine($"Recovered config from backup after primary read failed: {primaryError.Message}");
                        return backup;
                    }
                    catch (Exception backupError)
                    {
                        throw new InvalidOperationException("Không thể đọc config.json hoặc bản sao lưu.", backupError);
                    }
                }
            });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to load config: {ex}");
            throw new InvalidOperationException("Không thể đọc cấu hình ứng dụng. Key được giữ nguyên; vui lòng thử lại.", ex);
        }
    }

    private void UpdateConfig(Action<AppConfig> update)
    {
        WithConfigMutex(() =>
        {
            var config = ReadConfigUnsafe();
            update(config);
            WriteConfigUnsafe(config);
            return true;
        });
    }

    public ApiService()
    {
        AppPaths.EnsureDirectoriesAndMigrateLegacyConfig();
    }

    public AppConfig GetConfigSnapshot()
    {
        return LoadConfig();
    }

    public async Task<StatusResponse?> GetStatusAsync()
    {
        var config = LoadConfig();
        var activeProxy = config.SavedProxies.FirstOrDefault(p => p.Id == config.ActiveProxyId);
        if (IsWireGuardProxy(activeProxy) && config.ProxyMode == "all")
        {
            string nodeId = GetWireGuardNodeId(activeProxy);
            string tunnelBaseName = AppPaths.WireGuardTunnelBaseName(nodeId);
            string statusCommand = nodeId.Length > 0 ? "STATUS|" + nodeId : "STATUS";
            VpnServiceReply serviceReply = await VpnServiceClient.SendAsync(statusCommand, 1500);
            bool? reportedRunning = serviceReply.Available && serviceReply.Success && serviceReply.Fields.Length > 2
                ? serviceReply.Fields[1] == "running" && serviceReply.Fields[2] == "ready"
                : (bool?)null;
            bool running;
            if (reportedRunning.HasValue)
            {
                running = reportedRunning.Value;
            }
            else
            {
                // IPC timed out (service is busy with another command). Falling back
                // to WMI can also stall past the 1.5s budget. Preserve the previous
                // connection state to avoid spuriously reporting a tunnel that is
                // still up as "disconnected".
                lock (_connectionLock)
                {
                    if (_connectedState == "connected")
                    {
                        running = true;
                    }
                    else
                    {
                        running = IsWireGuardTunnelRunning(tunnelBaseName) && HasWireGuardInterface(tunnelBaseName);
                    }
                }
            }
            if (reportedRunning == false)
            {
                _wireGuardStatusFailures++;
                if (_wireGuardStatusFailures < WireGuardStatusFailureThreshold)
                {
                    lock (_connectionLock)
                        running = _connectedState == "connected" || _connectedState == "connecting" || _connectedState == "reconnecting";
                }
                else
                {
                    // The native monitor owns WireGuard recovery. A status poll
                    // can be stale while the service is busy and must not tear
                    // down a tunnel on its own.
                    lock (_connectionLock)
                        running = _connectedState == "connected" || _connectedState == "connecting" || _connectedState == "reconnecting";
                }
            }
            else if (running)
            {
                _wireGuardStatusFailures = 0;
            }
            lock (_connectionLock)
            {
                if (running && _connectedState != "connecting")
                {
                    _connectedState = "connected";
                    _connectionStartTime ??= DateTime.Now;
                }
                else if (!running && _connectedState == "connected")
                {
                    _connectedState = "disconnected";
                    _connectionStartTime = null;
                    _currentPublicIp = "--";
                    _currentLatency = 0;
                    Volatile.Write(ref _lastError, "WireGuard tunnel đã dừng.");
                }
            }

            int wireGuardDuration = _connectionStartTime.HasValue && _connectedState == "connected"
                ? (int)(DateTime.Now - _connectionStartTime.Value).TotalSeconds
                : 0;
            (long downloadTotal, long uploadTotal) = GetWireGuardTrafficTotals(tunnelBaseName);
            return new StatusResponse
            {
                State = _connectedState,
                Duration = wireGuardDuration,
                PublicIp = _currentPublicIp,
                Latency = _currentLatency,
                LocalPort = config.LocalPort,
                ActiveProxy = activeProxy,
                Theme = config.Theme,
                UseVpnMode = true,
                IsAdmin = CheckAdminStatus(),
                StartOnBoot = config.StartOnBoot,
                DownloadTotal = downloadTotal,
                UploadTotal = uploadTotal,
                AutoReconnect = true,
                LastError = Volatile.Read(ref _lastError)
            };
        }

        Process? process;
        lock (_connectionLock) { process = _singBoxProcess; }
        // The connection task owns process-exit handling (including reconnect).
        // Only reap here when no task is active, so a crash observed between
        // polls cannot leave a stale "connected" state behind.
        bool watchdogActive;
        lock (_connectionLock) { watchdogActive = _connectionTask != null && !_connectionTask.IsCompleted; }
        if (_connectedState == "connected" && !IsProcessRunning(process) && !watchdogActive)
        {
            bool ownedCurrentProcess = false;
            lock (_connectionLock)
            {
                if (ReferenceEquals(process, _singBoxProcess))
                {
                    ownedCurrentProcess = true;
                    _singBoxProcess = null;
                    _connectedState = "disconnected";
                    _connectionStartTime = null;
                    _currentPublicIp = "--";
                    _currentLatency = 0;
                    _currentDownloadTotal = 0;
                    _currentUploadTotal = 0;
                }
            }
            if (ownedCurrentProcess)
            {
                SetSystemProxy(false);
                StopOwnedProcess(process);
            }
        }

        int duration = 0;
        if (_connectionStartTime.HasValue && _connectedState == "connected")
        {
            duration = (int)(DateTime.Now - _connectionStartTime.Value).TotalSeconds;
        }

        if (_connectedState == "connected" && IsProcessRunning(process))
        {
            try
            {
                var traffic = await GetFromClashApiAsync<ClashConnectionsResponse>("/connections");
                if (traffic != null)
                {
                    _currentDownloadTotal = traffic.DownloadTotal;
                    _currentUploadTotal = traffic.UploadTotal;
                }
            }
            catch
            {
                // Keep the last UI sample cycle stable if Clash API is temporarily unavailable.
            }
        }

        return new StatusResponse
        {
            State = _connectedState,
            Duration = duration,
            PublicIp = _currentPublicIp,
            Latency = _currentLatency,
            LocalPort = config.LocalPort,
            ActiveProxy = activeProxy,
            Theme = config.Theme,
            UseVpnMode = config.UseVpnMode,
            IsAdmin = CheckAdminStatus(),
            StartOnBoot = config.StartOnBoot,
            DownloadTotal = _currentDownloadTotal,
            UploadTotal = _currentUploadTotal,
            AutoReconnect = config.AutoReconnect,
            ReconnectAttempt = Volatile.Read(ref _reconnectAttempt),
            ReconnectDelay = Volatile.Read(ref _reconnectDelay),
            LastError = Volatile.Read(ref _lastError)
        };
    }

    public async Task<ProxiesResponse?> GetProxiesAsync()
    {
        var config = LoadConfig();
        NormalizeManagedProxyNames(config.SavedProxies);
        return new ProxiesResponse
        {
            Proxies = config.SavedProxies,
            ActiveId = config.ActiveProxyId,
            LocalPort = config.LocalPort
        };
    }

    public async Task<ProcessesResponse?> GetProcessesAsync()
    {
        var config = LoadConfig();
        var activeProxy = config.SavedProxies.FirstOrDefault(p => p.Id == config.ActiveProxyId);
        var response = new ProcessesResponse
        {
            ProxyMode = config.ProxyMode,
            AllowedProcesses = config.AllowedProcesses,
            ActiveConnections = new List<ConnectionInfo>()
        };

        if (_connectedState != "connected")
        {
            return response;
        }

        if (IsWireGuardProxy(activeProxy) && config.ProxyMode == "all")
        {
            response.ActiveConnections = GetWireGuardConnections();
            return response;
        }

        try
        {
            // Fetch live connection list from Clash API built into sing-box
            var clashRes = await GetFromClashApiAsync<ClashConnectionsResponse>("/connections");
            if (clashRes != null && clashRes.Connections != null)
            {
                foreach (var conn in clashRes.Connections)
                {
                    string name = "System / Unknown";
                    string path = "";
                    if (!string.IsNullOrEmpty(conn.Metadata.ProcessPath))
                    {
                        path = conn.Metadata.ProcessPath;
                        name = Path.GetFileName(path);
                    }

                    string dest = conn.Metadata.Host;
                    if (string.IsNullOrEmpty(dest))
                    {
                        dest = $"{conn.Metadata.DestinationIP}:{conn.Metadata.DestinationPort}";
                    }

                    string route = "Direct";
                    // Match the outbound tag exactly; a substring test would also
                    // match unrelated tags that merely contain "proxy".
                    if (conn.Chains != null && conn.Chains.Any(c => string.Equals(c, "proxy-out", StringComparison.OrdinalIgnoreCase)))
                    {
                        route = "Proxy";
                    }

                    response.ActiveConnections.Add(new ConnectionInfo
                    {
                        Id = conn.Id,
                        Pid = 0,
                        Name = name,
                        Path = path,
                        Dest = dest,
                        Route = route,
                        Sent = conn.Upload,
                        Recv = conn.Download,
                        Status = "Active",
                        Time = conn.Start
                    });
                }
            }
        }
        catch {}

        return response;
    }

    public async Task<GenericResponse?> ConnectAsync()
    {
        var config = LoadConfig();
        var activeProxy = config.SavedProxies.FirstOrDefault(p => p.Id == config.ActiveProxyId);

        if (activeProxy == null)
        {
            return new GenericResponse { Success = false, Message = "Chưa chọn proxy hoạt động nào!" };
        }

        if (IsWireGuardProxy(activeProxy) && config.ProxyMode == "all")
        {
            int nativeGeneration;
            lock (_connectionLock)
            {
                if (_connectedState == "connected") return new GenericResponse { Success = true, Message = "Đã kết nối rồi." };
                if (_connectedState == "connecting" || _connectedState == "reconnecting")
                    return new GenericResponse { Success = true, Message = "Đang kết nối." };
                nativeGeneration = ++_connectionGeneration;
                _connectedState = "connecting";
                _currentPublicIp = "--";
                _currentLatency = 0;
                _currentDownloadTotal = 0;
                _currentUploadTotal = 0;
                Volatile.Write(ref _lastError, string.Empty);
            }

            // The native handshake waits on the service and the adapter, so run it
            // in the background and let the status poll report the outcome.
            _connectionTask = Task.Run(() => RunWireGuardConnectionAsync(nativeGeneration));
            return new GenericResponse { Success = true, Message = "Bắt đầu kết nối..." };
        }

        if (IsWireGuardProxy(activeProxy))
        {
            if (config.ProxyMode == "selected_only" && config.AllowedProcesses.Count == 0)
            {
                return new GenericResponse
                {
                    Success = false,
                    Message = "Hãy thêm ít nhất một ứng dụng trước khi dùng chế độ chỉ định tuyến ứng dụng đã chọn."
                };
            }
            GenericResponse nativeStop;
            await _nativeLifecycle.WaitAsync();
            try { nativeStop = await StopWireGuardAsync(); }
            finally { _nativeLifecycle.Release(); }
            if (!nativeStop.Success)
            {
                return new GenericResponse
                {
                    Success = false,
                    Message = "Không thể chuyển WireGuard sang định tuyến theo ứng dụng: " + nativeStop.Message
                };
            }
        }

        try
        {
            VerifyThirdPartyFiles();
        }
        catch (Exception ex)
        {
            return new GenericResponse { Success = false, Message = ex.Message };
        }

        lock (_connectionLock)
        {
            if (_connectedState == "connected")
            {
                return new GenericResponse { Success = true, Message = "Đã kết nối rồi." };
            }
            if (_connectedState == "connecting" || _connectedState == "reconnecting")
            {
                return new GenericResponse { Success = true, Message = "Đang kết nối." };
            }

            _connectedState = "connecting";
            _currentPublicIp = "--";
            _currentLatency = 0;
            _currentDownloadTotal = 0;
            _currentUploadTotal = 0;
            _reconnectAttempt = 0;
            _reconnectDelay = 0;
            Volatile.Write(ref _lastError, string.Empty);
            _connectionCts = new CancellationTokenSource();
            int generation = ++_connectionGeneration;
            CancellationToken token = _connectionCts.Token;
            _connectionTask = Task.Run(() => RunConnectionAsync(activeProxy, config, generation, token));
        }

        // Return as soon as the attempt is queued so the caller can paint the
        // "connecting" state; the status poll reports success or the failure
        // reason once the handshake finishes.
        return new GenericResponse { Success = true, Message = "Bắt đầu kết nối..." };
    }

    private async Task RunWireGuardConnectionAsync(int nativeGeneration)
    {
        await _nativeLifecycle.WaitAsync();
        try
        {
            GenericResponse result = await StartWireGuardAsync();
            AppConfig config = LoadConfig();
            Proxy? activeProxy = config.SavedProxies.FirstOrDefault(p => p.Id == config.ActiveProxyId);
            string tunnelBaseName = AppPaths.WireGuardTunnelBaseName(GetWireGuardNodeId(activeProxy));
            bool ownsGeneration;
            lock (_connectionLock)
            {
                ownsGeneration = nativeGeneration == _connectionGeneration;
                if (ownsGeneration && result.Success)
                {
                    _connectedState = "connected";
                    _connectionStartTime = DateTime.Now;
                    _currentPublicIp = string.IsNullOrWhiteSpace(result.Ip) ? "--" : result.Ip;
                    _currentLatency = result.Latency;
                    StartWireGuardMonitor(nativeGeneration, tunnelBaseName);
                }
                else if (ownsGeneration)
                {
                    _connectedState = "disconnected";
                    _connectionStartTime = null;
                    Volatile.Write(ref _lastError, result.Message);
                }
            }
            if (!ownsGeneration) await StopWireGuardAsync();
        }
        catch (Exception ex)
        {
            // Nothing awaits this task, so a swallowed failure would leave the UI
            // stuck on "connecting" forever.
            lock (_connectionLock)
            {
                if (nativeGeneration == _connectionGeneration)
                {
                    _connectedState = "disconnected";
                    _connectionStartTime = null;
                    Volatile.Write(ref _lastError, ex.Message);
                }
            }
        }
        finally { _nativeLifecycle.Release(); }
    }

    private async Task RunConnectionAsync(Proxy activeProxy, AppConfig config, int generation, CancellationToken cancellationToken)
    {
        // Attempt 0 is the initial connect; later attempts are bounded retries
        // after an unexpected sing-box exit.
        for (int attempt = 0; ; attempt++)
        {
            if (attempt > 0)
            {
                int delaySeconds = ReconnectDelaysSeconds[Math.Min(attempt - 1, ReconnectDelaysSeconds.Length - 1)];
                lock (_connectionLock)
                {
                    if (generation != _connectionGeneration) return;
                    _connectedState = "reconnecting";
                    _reconnectAttempt = attempt;
                    _reconnectDelay = delaySeconds;
                }

                try { await Task.Delay(TimeSpan.FromSeconds(delaySeconds), cancellationToken); }
                catch (OperationCanceledException) { return; }

                // Re-read config so a proxy or mode change applies to the retry.
                config = LoadConfig();
                Proxy? refreshed = config.SavedProxies.FirstOrDefault(p => p.Id == config.ActiveProxyId);
                if (refreshed == null)
                {
                    SetFailureState(generation, "Không tìm thấy proxy hoạt động.");
                    return;
                }
                activeProxy = refreshed;
            }

            lock (_connectionLock)
            {
                if (generation != _connectionGeneration) return;
                _reconnectDelay = 0;
            }

            Process? launchedProcess = await TryEstablishConnectionAsync(activeProxy, config, generation, cancellationToken);
            if (launchedProcess == null)
            {
                // Establishing failed. Retry only when the user opted in and this
                // generation is still current.
                bool keepTrying;
                lock (_connectionLock) { keepTrying = generation == _connectionGeneration; }
                if (!keepTrying || cancellationToken.IsCancellationRequested) return;
                if (!LoadConfig().AutoReconnect || attempt >= ReconnectDelaysSeconds.Length)
                {
                    string failure = Volatile.Read(ref _lastError) is { Length: > 0 } existing
                        ? existing
                        : "Không thể kết nối.";
                    SetFailureState(generation, failure);
                    return;
                }
                continue;
            }

            bool wasEstablished;
            lock (_connectionLock)
            {
                wasEstablished = generation == _connectionGeneration;
                if (wasEstablished)
                {
                    _reconnectAttempt = 0;
                    _reconnectDelay = 0;
                    Volatile.Write(ref _lastError, string.Empty);
                }
            }

            // The monitor only stops this exact child after repeated failures;
            // the existing process watcher remains the sole reconnect owner.
            Task<int> processExitTask = WaitForProcessExitAsync(launchedProcess, cancellationToken);
            Task healthTask = MonitorConnectionHealthAsync(launchedProcess, config, generation, cancellationToken);
            await Task.WhenAny(processExitTask, healthTask);
            int exitCode = await processExitTask;
            bool ownsGeneration;
            lock (_connectionLock)
            {
                ownsGeneration = generation == _connectionGeneration;
                if (ownsGeneration && ReferenceEquals(_singBoxProcess, launchedProcess))
                {
                    _singBoxProcess = null;
                }
            }

            if (!ownsGeneration || cancellationToken.IsCancellationRequested)
            {
                StopOwnedProcess(launchedProcess);
                return;
            }

            // Unexpected exit while the user still wants a connection.
            StopOwnedProcess(launchedProcess);
            SetSystemProxy(false);
            string reason = $"sing-box đã dừng (mã {exitCode}).";
            Volatile.Write(ref _lastError, reason);
            lock (_connectionLock)
            {
                if (generation != _connectionGeneration) return;
                _connectedState = "reconnecting";
                _connectionStartTime = null;
                _currentPublicIp = "--";
                _currentLatency = 0;
            }

            if (!LoadConfig().AutoReconnect || attempt >= ReconnectDelaysSeconds.Length)
            {
                SetFailureState(generation, reason);
                return;
            }

            // A connection that was actually established earns a fresh retry
            // budget, so a long-lived tunnel dying once does not start at the
            // maximum backoff or find the budget already spent.
            if (wasEstablished) attempt = 0;
        }
    }

    private static void SetFailureState(int generation, string message)
    {
        Volatile.Write(ref _lastError, message);
        bool owns;
        lock (_connectionLock)
        {
            owns = generation == _connectionGeneration;
            if (owns)
            {
                _connectedState = "disconnected";
                _connectionStartTime = null;
                _currentPublicIp = "--";
                _currentLatency = 0;
                _reconnectAttempt = 0;
                _reconnectDelay = 0;
            }
        }
        if (owns) SetSystemProxy(false);
    }

    private static async Task<int> WaitForProcessExitAsync(Process process, CancellationToken cancellationToken)
    {
        var completion = new TaskCompletionSource<int>();
        void OnExited(object? sender, EventArgs e)
        {
            try { completion.TrySetResult(process.ExitCode); }
            catch { completion.TrySetResult(-1); }
        }

        process.EnableRaisingEvents = true;
        process.Exited += OnExited;
        try
        {
            if (process.HasExited)
            {
                try { return process.ExitCode; } catch { return -1; }
            }

            using (cancellationToken.Register(() => completion.TrySetCanceled()))
            {
                try { return await completion.Task; }
                catch (TaskCanceledException) { return -1; }
            }
        }
        finally
        {
            process.Exited -= OnExited;
        }
    }

    /// <summary>
    /// Launches sing-box and promotes the connection to "connected".
    /// Returns the running process, or null when the attempt failed.
    /// </summary>
    private async Task<Process?> TryEstablishConnectionAsync(Proxy activeProxy, AppConfig config, int generation, CancellationToken cancellationToken)
    {
        Process? launchedProcess = null;
        bool established = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Rotate the Clash API secret before rendering the config so the running
            // sing-box instance and our own API calls always share the same token.
            Volatile.Write(ref _clashApiSecret, GenerateSecret());
            string tunInterfaceName = $"292vpn-{new Random().Next(1000, 9999)}";
            string configJson = GenerateSingBoxConfig(activeProxy, config, tunInterfaceName);
            WriteRuntimeSingBoxConfig(configJson);

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string singboxExe = Path.Combine(baseDir, "sing-box.exe");
            var startInfo = new ProcessStartInfo
            {
                FileName = singboxExe,
                Arguments = "run -c \"" + AppPaths.SingBoxConfigFile + "\"",
                WorkingDirectory = baseDir,
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden,
                // A config sing-box rejects is reported on stderr and the process
                // exits before it ever opens its log file, so without this the
                // failure leaves no trace anywhere.
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            launchedProcess = Process.Start(startInfo);
            if (launchedProcess == null) throw new InvalidOperationException("Không thể khởi động sing-box.");
            var startupErrors = new StringBuilder();
            launchedProcess.ErrorDataReceived += (_, e) =>
            {
                if (e.Data == null) return;
                lock (startupErrors)
                {
                    if (startupErrors.Length < 4096) startupErrors.AppendLine(e.Data);
                }
                AppendBoundedSingBoxLog(AppPaths.SingBoxStderrLogFile, e.Data);
            };
            launchedProcess.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null) AppendBoundedSingBoxLog(AppPaths.SingBoxLogFile, e.Data);
            };
            launchedProcess.BeginOutputReadLine();
            launchedProcess.BeginErrorReadLine();
            lock (_connectionLock)
            {
                if (generation != _connectionGeneration) throw new OperationCanceledException();
                _singBoxProcess = launchedProcess;
            }

            for (int attempt = 0; attempt < 20; attempt++)
            {
                await Task.Delay(500, cancellationToken);
                if (!IsProcessRunning(launchedProcess) || !config.UseVpnMode || HasTunInterface(tunInterfaceName)) break;
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (!IsProcessRunning(launchedProcess) || (config.UseVpnMode && !HasTunInterface(tunInterfaceName)))
            {
                string detail;
                lock (startupErrors) detail = startupErrors.ToString().Trim();
                throw new InvalidOperationException(detail.Length > 0
                    ? "sing-box không khởi tạo được giao diện VPN: " + detail
                    : "sing-box không khởi tạo được giao diện VPN.");
            }

            // The system proxy is a machine-wide setting that WinINet apps obey
            // regardless of our per-process route rules, so it would drag
            // unselected apps through the tunnel in split-tunnel mode. In VPN
            // mode the TUN already carries everything, so the system proxy is
            // only needed for proxy mode with every app routed.
            bool useSystemProxy = !config.UseVpnMode && config.ProxyMode == "all";
            if (useSystemProxy)
            {
                SetSystemProxy(true, "127.0.0.1", config.LocalPort);
            }
            lock (_connectionLock)
            {
                if (generation != _connectionGeneration) throw new OperationCanceledException();
                _connectedState = "connecting";
            }

            ProxyTestResult check = new() { Success = false, Message = "Tunnel chưa sẵn sàng" };
            for (int attempt = 0; attempt < 3 && IsProcessRunning(launchedProcess); attempt++)
            {
                check = await CheckConnectionThroughProxyAsync(
                    config.UseVpnMode,
                    config.LocalPort,
                    cancellationToken);
                if (check.Success) break;
                if (attempt < 2) await Task.Delay(1000, cancellationToken);
            }
            if (!check.Success)
            {
                throw new InvalidOperationException(
                    "Tunnel không truyền được dữ liệu: " + (check.Message ?? "không rõ nguyên nhân"));
            }

            lock (_connectionLock)
            {
                if (generation == _connectionGeneration && check.Success)
                {
                    _connectedState = "connected";
                    _connectionStartTime = DateTime.Now;
                    _currentLatency = check.Latency;
                }
            }
            _ = UpdatePublicIpAsync(
                launchedProcess,
                config.UseVpnMode,
                config.LocalPort,
                generation,
                cancellationToken);
            DeleteRuntimeSingBoxConfig();

            established = true;
            return launchedProcess;
        }
        catch (OperationCanceledException) { return null; }
        catch (Exception ex)
        {
            Debug.WriteLine($"Connection failed: {ex.Message}");
            Volatile.Write(ref _lastError, ex.Message);
            return null;
        }
        finally
        {
            if (!established)
            {
                bool ownsGeneration;
                lock (_connectionLock)
                {
                    ownsGeneration = generation == _connectionGeneration;
                    if (ownsGeneration && _connectedState != "disconnected")
                    {
                        _connectedState = "disconnected";
                        _connectionStartTime = null;
                        _reconnectAttempt = 0;
                        _reconnectDelay = 0;
                    }
                    if (launchedProcess != null && ReferenceEquals(_singBoxProcess, launchedProcess))
                    {
                        _singBoxProcess = null;
                    }
                }
                if (ownsGeneration) SetSystemProxy(false);
                StopOwnedProcess(launchedProcess);
                DeleteRuntimeSingBoxConfig();
            }
        }
    }

    private static void DeleteRuntimeSingBoxConfig()
    {
        try
        {
            if (File.Exists(AppPaths.SingBoxConfigFile)) File.Delete(AppPaths.SingBoxConfigFile);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to delete runtime sing-box config: {ex.Message}");
        }
    }

    private static void WriteRuntimeSingBoxConfig(string configJson)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        using var stream = new FileStream(
            AppPaths.SingBoxConfigFile,
            FileMode.Create,
            FileSystemRights.Write,
            FileShare.Read,
            4096,
            FileOptions.SequentialScan,
            security);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        writer.Write(configJson);
    }

    public async Task<ManagedLoginResponse?> ManagedLoginAsync(string apiUrl, string username, string password)
    {
        if (!Uri.TryCreate(apiUrl.Trim().TrimEnd('/'), UriKind.Absolute, out Uri? baseUri) ||
            !baseUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Managed API phải dùng địa chỉ HTTPS hợp lệ.");
        }

        string deviceId = GetOrCreateManagedDeviceId();
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(15), BaseAddress = baseUri };
        using var response = await client.PostAsJsonAsync("/v1/auth/login", new
        {
            username,
            password,
            device_id = deviceId,
            device_name = Environment.MachineName
        });
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<ManagedLoginResponse>();
        if (result == null || string.IsNullOrWhiteSpace(result.AccessToken)) throw new InvalidOperationException("API không trả access token.");
        UpdateConfig(config =>
        {
            config.ManagedApiUrl = baseUri.ToString().TrimEnd('/');
            config.ManagedUsername = username.Trim();
            config.ManagedAccessToken = result.AccessToken;
        });
        return result;
    }

    public async Task<List<ManagedNode>> GetManagedNodesAsync()
    {
        var config = GetConfigSnapshot();
        using var client = CreateManagedClient(config);
        using var response = await client.GetAsync("/v1/nodes");
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<ManagedNodesResponse>())?.Nodes ?? new List<ManagedNode>();
    }

    public async Task<List<ManagedNodeCandidate>> GetManagedNodeCandidatesAsync()
    {
        var config = GetConfigSnapshot();
        using var client = CreateManagedClient(config);
        using var response = await client.GetAsync("/v1/nodes/candidates");
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<ManagedNodeCandidatesResponse>())?.Candidates
            ?? new List<ManagedNodeCandidate>();
    }

    public async Task<ManagedNodeReportResponse> ReportManagedNodeHealthAsync(
        string endpointId,
        IReadOnlyDictionary<string, bool> checks)
    {
        if (string.IsNullOrWhiteSpace(endpointId) || checks.Count == 0)
        {
            throw new ArgumentException("Endpoint và kết quả health check là bắt buộc.");
        }

        var config = GetConfigSnapshot();
        using var client = CreateManagedClient(config);
        using var response = await client.PostAsJsonAsync("/v1/nodes/report", new
        {
            endpoint_id = endpointId.Trim(),
            checks
        });
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<ManagedNodeReportResponse>()
            ?? throw new InvalidOperationException("API không trả kết quả health check hợp lệ.");
    }

    public async Task<ManagedConfigResponse> IssueManagedConfigAsync(string nodeId)
    {
        var config = GetConfigSnapshot();
        using var client = CreateManagedClient(config);
        using var response = await client.PostAsJsonAsync("/v1/configs/issue", new { node_id = nodeId });
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<ManagedConfigResponse>();
        if (result == null || string.IsNullOrWhiteSpace(result.ConfigUrl)) throw new InvalidOperationException("API không trả cấu hình VLESS.");
        UpdateConfig(saved =>
        {
            saved.ManagedNodeId = result.NodeId;
            var proxy = saved.SavedProxies.FirstOrDefault(p => p.Id == "managed-" + result.NodeId);
            if (proxy == null)
            {
                saved.SavedProxies.Add(new Proxy { Id = "managed-" + result.NodeId, Name = result.Name, Type = "URL", Ip = result.ConfigUrl });
            }
            else
            {
                proxy.Name = result.Name;
                proxy.Ip = result.ConfigUrl;
            }
            saved.ActiveProxyId = "managed-" + result.NodeId;
        });
        return result;
    }

    public async Task<VpnSessionResponse> ActivateVpnAsync(string key)
    {
        string installationId = GetOrCreateManagedDeviceId();
        string deviceId;
        using (var sha256 = SHA256.Create())
        {
            deviceId = BitConverter.ToString(sha256.ComputeHash(Encoding.UTF8.GetBytes(installationId))).Replace("-", "").ToLowerInvariant();
        }
        using var client = CreateVpnClient();
        using var response = await SendVpnRequestAsync(
            () => client.PostAsJsonAsync("/api/vpn/activate", new { key = key.Trim(), uid = deviceId }),
            "Xác thực license");
        var result = await response.Content.ReadFromJsonAsync<VpnSessionResponse>();
        if (result == null || string.IsNullOrWhiteSpace(result.Token)) throw new InvalidOperationException("Account server không trả phiên VPN hợp lệ.");
        return result;
    }

    public void SaveVpnLicenseKey(string key)
    {
        UpdateConfig(config => config.VpnLicenseKey = key.Trim().ToUpperInvariant());
    }

    public void ClearVpnLicenseKey()
    {
        UpdateConfig(config => config.VpnLicenseKey = string.Empty);
    }

    public async Task<VpnHeartbeatResponse> HeartbeatVpnAsync(string token, int sequence)
    {
        using var client = CreateVpnClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        using var response = await client.PostAsJsonAsync("/api/vpn/heartbeat", new { sequence });
        if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
        {
            HttpStatusCode statusCode = response.StatusCode;
            response.Dispose();
            // A 401/403 means the server no longer knows this session (deploy
            // reset the database, lease expired, or the key was revoked). The
            // UI must return to activation instead of silently continuing.
            throw new VpnApiStatusException(statusCode, "Phiên VPN đã hết hạn hoặc bị thu hồi.");
        }
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<VpnHeartbeatResponse>() ?? throw new InvalidOperationException("Heartbeat VPN không hợp lệ.");
    }

    public async Task LogoutVpnAsync(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return;
        using var client = CreateVpnClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        using var response = await client.PostAsJsonAsync("/api/vpn/logout", new { });
        response.EnsureSuccessStatusCode();
    }

    public async Task<VpnConfigResponse> IssueVpnConfigAsync(string token, string nodeId = "vn-hanoi-1")
    {
        using var client = CreateVpnClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        using var response = await SendVpnRequestAsync(
            () => client.PostAsJsonAsync("/api/vpn/configs/issue", new { node_id = nodeId }),
            $"Cấp cấu hình cho {nodeId}");
        var result = await response.Content.ReadFromJsonAsync<VpnConfigResponse>();
        if (result == null || (string.IsNullOrWhiteSpace(result.ConfigUrl) && string.IsNullOrWhiteSpace(result.ConfigText)))
            throw new InvalidOperationException("Account server không trả cấu hình VPN.");
        return result;
    }

    internal sealed class VpnApiStatusException : InvalidOperationException
    {
        public HttpStatusCode StatusCode { get; }

        public VpnApiStatusException(HttpStatusCode statusCode, string message) : base(message)
        {
            StatusCode = statusCode;
        }
    }

    private static async Task<HttpResponseMessage> SendVpnRequestAsync(
        Func<Task<HttpResponseMessage>> send,
        string operation)
    {
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            HttpResponseMessage response;
            try
            {
                response = await send();
            }
            // An account server update restarts the process and drops in-flight
            // connections; without a retry every activation and node refresh
            // fails the moment the deploy lands.
            catch (Exception ex) when (attempt < 3 && (ex is HttpRequestException || ex is TaskCanceledException))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500 * attempt));
                continue;
            }

            if (response.StatusCode == HttpStatusCode.ServiceUnavailable && attempt < 3)
            {
                response.Dispose();
                await Task.Delay(TimeSpan.FromMilliseconds(500 * attempt));
                continue;
            }

            if (response.IsSuccessStatusCode) return response;

            string detail = string.Empty;
            try { detail = (await response.Content.ReadAsStringAsync()).Trim(); } catch {}
            HttpStatusCode statusCode = response.StatusCode;
            response.Dispose();
            string message = statusCode == HttpStatusCode.ServiceUnavailable
                ? $"{operation}: máy chủ tạm thời không khả dụng (503)."
                : $"{operation}: máy chủ trả lỗi {(int)statusCode}.";
            if (!string.IsNullOrWhiteSpace(detail) && detail.Length <= 300) message += " " + detail;
            throw new VpnApiStatusException(statusCode, message);
        }

        throw new InvalidOperationException($"{operation}: không thể kết nối máy chủ.");
    }

    public async Task<List<VpnNode>> GetVpnNodesAsync(string token)
    {
        using var client = CreateVpnClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        using var response = await SendVpnRequestAsync(
            () => client.GetAsync("/api/vpn/nodes"),
            "Tải danh sách máy chủ VPN");
        return (await response.Content.ReadFromJsonAsync<VpnNodesResponse>())?.Nodes ?? new List<VpnNode>();
    }

    public void ReplaceManagedVpnProxies(IEnumerable<Proxy> proxies)
    {
        var replacements = proxies.ToList();
        NormalizeManagedProxyNames(replacements);
        UpdateConfig(config =>
        {
            var replacementIds = new HashSet<string>(
                replacements.Select(proxy => proxy.Id), StringComparer.OrdinalIgnoreCase);
            config.SavedProxies.RemoveAll(proxy =>
                proxy.Id.StartsWith("managed-", StringComparison.OrdinalIgnoreCase) &&
                !replacementIds.Contains(proxy.Id));
            foreach (Proxy replacement in replacements)
            {
                int index = config.SavedProxies.FindIndex(proxy =>
                    string.Equals(proxy.Id, replacement.Id, StringComparison.OrdinalIgnoreCase));
                if (index >= 0) config.SavedProxies[index] = replacement;
                else config.SavedProxies.Insert(0, replacement);
            }
            if (!config.SavedProxies.Any(proxy =>
                string.Equals(proxy.Id, config.ActiveProxyId, StringComparison.OrdinalIgnoreCase)))
            {
                config.ActiveProxyId = replacements.FirstOrDefault()?.Id ?? config.SavedProxies.FirstOrDefault()?.Id ?? string.Empty;
            }
        });
    }

    private static HttpClient CreateManagedClient(AppConfig config)
    {
        if (!Uri.TryCreate(config.ManagedApiUrl, UriKind.Absolute, out Uri? baseUri) ||
            !baseUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(config.ManagedAccessToken))
        {
            throw new InvalidOperationException("Chưa đăng nhập Managed API.");
        }
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(15), BaseAddress = baseUri };
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", config.ManagedAccessToken);
        return client;
    }

    private HttpClient CreateVpnClient()
    {
        var config = GetConfigSnapshot();
        if (!Uri.TryCreate(config.ManagedApiUrl, UriKind.Absolute, out Uri? baseUri) ||
            !baseUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Managed API phải dùng địa chỉ HTTPS hợp lệ.");
        }
        if (!string.Equals(baseUri.Host, DefaultManagedApiHost, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("VPN API phải dùng máy chủ account đã được tin cậy.");
        return new HttpClient { Timeout = TimeSpan.FromSeconds(15), BaseAddress = baseUri };
    }

    private string GetOrCreateManagedDeviceId()
    {
        var config = GetConfigSnapshot();
        if (!string.IsNullOrWhiteSpace(config.ManagedDeviceId)) return config.ManagedDeviceId;
        string deviceId = Guid.NewGuid().ToString("N");
        UpdateConfig(saved => saved.ManagedDeviceId = deviceId);
        return deviceId;
    }

    private async Task MonitorConnectionHealthAsync(
        Process process,
        AppConfig config,
        int generation,
        CancellationToken cancellationToken)
    {
        int consecutiveFailures = 0;
        while (!cancellationToken.IsCancellationRequested && IsProcessRunning(process))
        {
            try
            {
                await Task.Delay(HealthCheckInterval, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (cancellationToken.IsCancellationRequested || !IsProcessRunning(process)) return;

            ProxyTestResult check = await CheckConnectionThroughProxyAsync(
                config.UseVpnMode,
                config.LocalPort,
                cancellationToken);
            if (check.Success)
            {
                consecutiveFailures = 0;
                lock (_connectionLock)
                {
                    if (generation == _connectionGeneration && ReferenceEquals(_singBoxProcess, process))
                    {
                        _currentLatency = check.Latency;
                        Volatile.Write(ref _lastError, string.Empty);
                    }
                }
                continue;
            }

            consecutiveFailures++;
            lock (_connectionLock)
            {
                if (generation != _connectionGeneration || !ReferenceEquals(_singBoxProcess, process)) return;
                Volatile.Write(ref _lastError, $"Health check thất bại ({consecutiveFailures}/{HealthFailureThreshold}): {check.Message}");
            }
            if (consecutiveFailures < HealthFailureThreshold) continue;

            bool ownsProcess;
            lock (_connectionLock)
            {
                ownsProcess = generation == _connectionGeneration && ReferenceEquals(_singBoxProcess, process);
            }
            if (ownsProcess)
            {
                StopOwnedProcess(process, false);
            }
            return;
        }
    }

    private static string ProtectManagedToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.StartsWith("dpapi:", StringComparison.Ordinal)) return token;
        byte[] protectedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(token), null, DataProtectionScope.CurrentUser);
        return "dpapi:" + Convert.ToBase64String(protectedBytes);
    }

    private static string UnprotectManagedToken(string token)
    {
        if (!token.StartsWith("dpapi:", StringComparison.Ordinal)) return token;
        try
        {
            byte[] protectedBytes = Convert.FromBase64String(token.Substring("dpapi:".Length));
            return Encoding.UTF8.GetString(ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser));
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("Không thể giải mã dữ liệu bảo mật của cấu hình hiện tại.", ex);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("Dữ liệu bảo mật trong cấu hình không hợp lệ.", ex);
        }
    }

    public async Task<GenericResponse?> DisconnectAsync()
    {
        Task? task;
        Process? process;
        lock (_connectionLock)
        {
            ++_connectionGeneration;
            _connectionCts?.Cancel();
            _wireGuardMonitorCts?.Cancel();
            task = _connectionTask;
            process = _singBoxProcess;
            _singBoxProcess = null;
            _connectedState = "disconnected";
            _connectionStartTime = null;
            _currentPublicIp = "--";
            _currentLatency = 0;
            _currentDownloadTotal = 0;
            _currentUploadTotal = 0;
            // Manual disconnect must cancel any pending retry and clear stale errors.
            _reconnectAttempt = 0;
            _reconnectDelay = 0;
            Volatile.Write(ref _lastError, string.Empty);
        }

        GenericResponse wireGuardResult;
        await _nativeLifecycle.WaitAsync();
        try { wireGuardResult = await StopWireGuardAsync(); }
        finally { _nativeLifecycle.Release(); }
        SetSystemProxy(false);
        StopOwnedProcess(process, false);
        StopBundledSingBoxProcesses();
        if (task != null)
        {
            try { await task; } catch (OperationCanceledException) {} catch (Exception ex) { Debug.WriteLine(ex.Message); }
        }
        try { process?.Dispose(); } catch {}
        DeleteRuntimeSingBoxConfig();
        lock (_connectionLock)
        {
            if (ReferenceEquals(task, _connectionTask))
            {
                _connectionTask = null;
                _connectionCts?.Dispose();
                _connectionCts = null;
            }
        }

        return wireGuardResult.Success
            ? new GenericResponse { Success = true, Message = "Đã ngắt kết nối." }
            : wireGuardResult;
    }

    public async Task<GenericResponse> ConfigureWireGuardAsync(string nodeId, string configText)
    {
        if (!AppPaths.IsValidWireGuardNodeId(nodeId))
            return new GenericResponse { Success = false, Message = "Mã máy chủ WireGuard không hợp lệ." };
        if (string.IsNullOrWhiteSpace(configText))
            return new GenericResponse { Success = false, Message = "Account server không trả cấu hình WireGuard." };

        VpnServiceReply reply = await VpnServiceClient.SetWireGuardConfigAsync(nodeId, configText, 10000);
        return reply.Available && reply.Success
            ? new GenericResponse { Success = true, Message = "Đã lưu cấu hình WireGuard." }
            : new GenericResponse
            {
                Success = false,
                Message = "Không thể lưu cấu hình WireGuard" + FormatServiceError(reply) + "."
            };
    }

    public async Task<WireGuardStatus> GetWireGuardStatusAsync()
    {
        VpnServiceReply serviceReply = await VpnServiceClient.SendAsync("STATUS", 1500);
        string executable = GetWireGuardExecutablePath();
        bool installed = File.Exists(executable);
        bool configured;
        try
        {
            configured = Directory.Exists(AppPaths.WireGuardDirectory) &&
                Directory.EnumerateFiles(AppPaths.WireGuardDirectory, "292vpn-client*.conf").Any();
        }
        catch (UnauthorizedAccessException) { configured = true; }
        bool running = serviceReply.Available && serviceReply.Success && serviceReply.Fields.Length > 1
            ? serviceReply.Fields[1] == "running"
            : AnyManagedTunnelRunning();
        bool adapterReady = serviceReply.Available && serviceReply.Success && serviceReply.Fields.Length > 2
            ? serviceReply.Fields[2] == "ready"
            : HasAnyManagedWireGuardInterface();
        string publicIp = "--";
        if (running && adapterReady)
        {
            using var cts = new CancellationTokenSource(ProbeTimeout);
            var probe = await CheckConnectionThroughProxyAsync(true, 0, cts.Token);
            if (probe.Success) publicIp = probe.Ip;
        }
        return new WireGuardStatus
        {
            Installed = installed,
            Configured = configured,
            Running = running,
            AdapterReady = adapterReady,
            PublicIp = publicIp,
            Message = !installed
                ? "WireGuard for Windows chưa được cài đặt."
                : !configured
                    ? "Chưa có cấu hình WireGuard được cấp cho thiết bị."
                    : running && adapterReady
                        ? "WireGuard đang hoạt động."
                        : "WireGuard đã sẵn sàng nhưng chưa kết nối."
        };
    }

    public async Task<GenericResponse> StartWireGuardAsync()
    {
        var config = LoadConfig();
        var activeProxy = config.SavedProxies.FirstOrDefault(p => p.Id == config.ActiveProxyId);
        string nodeId = GetWireGuardNodeId(activeProxy);
        string tunnelBaseName = AppPaths.WireGuardTunnelBaseName(nodeId);
        string startCommand = nodeId.Length > 0 ? "START_WIREGUARD|" + nodeId : "START_WIREGUARD";
            VpnServiceReply serviceReply = await VpnServiceClient.SendCommandAsync(startCommand);
        if (serviceReply.Available)
        {
            if (!serviceReply.Success)
            {
                return new GenericResponse { Success = false, Message = "292VPN Service không thể khởi động WireGuard." };
            }
            using var serviceProbeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var serviceProbe = await CheckConnectionThroughProxyAsync(true, 0, serviceProbeCts.Token);
            if (!serviceProbe.Success)
            {
                await VpnServiceClient.SendCommandAsync("STOP_WIREGUARD");
                return new GenericResponse { Success = false, Message = "WireGuard không truyền được dữ liệu: " + serviceProbe.Message };
            }
            return new GenericResponse { Success = true, Message = "WireGuard đã kết nối qua 292VPN Service.", Ip = serviceProbe.Ip, Latency = serviceProbe.Latency };
        }

        return new GenericResponse
        {
            Success = false,
            Message = "292VPN Service không khả dụng; đã từ chối khởi động WireGuard không có kill switch."
        };
    }

    private void StartWireGuardRecoveryIfNeeded()
    {
        lock (_connectionLock)
        {
            if (_wireGuardRecoveryTask != null && !_wireGuardRecoveryTask.IsCompleted) return;
            if (_connectedState == "disconnected") return;
            _connectedState = "reconnecting";
            int generation = ++_connectionGeneration;
            _wireGuardRecoveryTask = Task.Run(() => RecoverWireGuardAsync(generation));
        }
    }

    private void StartWireGuardMonitor(int generation, string tunnelBaseName)
    {
        _wireGuardMonitorCts?.Cancel();
        var monitorCts = new CancellationTokenSource();
        _wireGuardMonitorCts = monitorCts;
        _wireGuardLastReceived = 0;
        _wireGuardLastSent = 0;
        _wireGuardTrafficSampled = false;
        _wireGuardMonitorTask = Task.Run(() => MonitorWireGuardAsync(generation, tunnelBaseName, monitorCts));
    }

    private async Task MonitorWireGuardAsync(int generation, string tunnelBaseName, CancellationTokenSource monitorCts)
    {
        int failures = 0;
        try
        {
            while (!monitorCts.IsCancellationRequested)
            {
                await Task.Delay(HealthCheckInterval, monitorCts.Token);
                if (monitorCts.IsCancellationRequested) return;

                WireGuardHealth health = ReadWireGuardHealth(tunnelBaseName);
                bool ownsGeneration;
                lock (_connectionLock)
                {
                    ownsGeneration = generation == _connectionGeneration &&
                        _connectedState == "connected";
                }
                if (!ownsGeneration) return;

                if (health.Healthy)
                {
                    failures = 0;
                    _wireGuardStatusFailures = 0;
                    lock (_connectionLock)
                    {
                        if (generation == _connectionGeneration)
                            Volatile.Write(ref _lastError, string.Empty);
                    }
                    continue;
                }

                failures++;
                _wireGuardStatusFailures = failures;
                lock (_connectionLock)
                {
                    if (generation != _connectionGeneration) return;
                    Volatile.Write(ref _lastError,
                        $"WireGuard health check thất bại ({failures}/{WireGuardStatusFailureThreshold}): {health.Message}");
                }
                if (failures < WireGuardStatusFailureThreshold) continue;

                StartWireGuardRecoveryIfNeeded();
                return;
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            if (ReferenceEquals(_wireGuardMonitorCts, monitorCts))
                _wireGuardMonitorCts = null;
            monitorCts.Dispose();
        }
    }

    private sealed class WireGuardHealth
    {
        public bool Healthy { get; set; }
        public string Message { get; set; } = "Không đọc được trạng thái WireGuard.";
    }

    private static WireGuardHealth ReadWireGuardHealth(string tunnelBaseName)
    {
        string executable = GetWireGuardCliPath();
        if (!File.Exists(executable)) return new WireGuardHealth { Message = "Thiếu wg.exe." };
        string handshakeOutput = RunProcessCapture(executable, "show " + tunnelBaseName + " latest-handshakes");
        string transferOutput = RunProcessCapture(executable, "show " + tunnelBaseName + " transfer");
        string output = handshakeOutput + Environment.NewLine + transferOutput;
        if (string.IsNullOrWhiteSpace(output)) return new WireGuardHealth();

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        bool recentHandshake = false;
        long received = 0;
        long sent = 0;
        foreach (string line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            string[] fields = line.Split('\t');
            if (fields.Length >= 2 && long.TryParse(fields[1], out long handshake) && handshake > 0 && now - handshake <= (long)WireGuardHandshakeMaxAge.TotalSeconds)
                recentHandshake = true;
            if (fields.Length >= 3 && long.TryParse(fields[1], out long rx) && long.TryParse(fields[2], out long tx))
            {
                received += rx;
                sent += tx;
            }
        }

        bool trafficIncreased = _wireGuardTrafficSampled && (received > _wireGuardLastReceived || sent > _wireGuardLastSent);
        _wireGuardLastReceived = received;
        _wireGuardLastSent = sent;
        _wireGuardTrafficSampled = true;
        return new WireGuardHealth
        {
            Healthy = recentHandshake || trafficIncreased,
            Message = recentHandshake ? "handshake còn mới" : trafficIncreased ? "transfer vẫn tăng" : "handshake quá cũ và transfer không tăng"
        };
    }

    private static string RunProcessCapture(string fileName, string arguments)
    {
        try
        {
            using (var process = Process.Start(new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WindowStyle = ProcessWindowStyle.Hidden
            }))
            {
                if (process == null) return string.Empty;
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(5000);
                return output;
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"WireGuard health command failed: {ex.Message}");
            return string.Empty;
        }
    }

    private async Task RecoverWireGuardAsync(int generation)
    {
        try
        {
            await _nativeLifecycle.WaitAsync();
            try
            {
                for (int attempt = 0; attempt < WireGuardRecoveryDelaysSeconds.Length; attempt++)
                {
                    int delay = WireGuardRecoveryDelaysSeconds[attempt];
                    lock (_connectionLock)
                    {
                        if (generation != _connectionGeneration) return;
                        _reconnectAttempt = attempt + 1;
                        _reconnectDelay = delay;
                    }
                    await Task.Delay(TimeSpan.FromSeconds(delay));
                    lock (_connectionLock) { if (generation != _connectionGeneration) return; }
                    await StopWireGuardAsync();
                    GenericResponse result = await StartWireGuardAsync();
                    if (result.Success)
                    {
                        lock (_connectionLock)
                        {
                            if (generation != _connectionGeneration) return;
                            _connectedState = "connected";
                            _connectionStartTime = DateTime.Now;
                            _currentPublicIp = string.IsNullOrWhiteSpace(result.Ip) ? "--" : result.Ip;
                            _currentLatency = result.Latency;
                            _wireGuardStatusFailures = 0;
                            _reconnectAttempt = 0;
                            _reconnectDelay = 0;
                            Volatile.Write(ref _lastError, string.Empty);
                        }
                        AppConfig config = LoadConfig();
                        Proxy? activeProxy = config.SavedProxies.FirstOrDefault(p => p.Id == config.ActiveProxyId);
                        StartWireGuardMonitor(generation, AppPaths.WireGuardTunnelBaseName(GetWireGuardNodeId(activeProxy)));
                        return;
                    }
                    Volatile.Write(ref _lastError, result.Message);
                }
                lock (_connectionLock)
                {
                    if (generation == _connectionGeneration)
                    {
                        _connectedState = "disconnected";
                        _connectionStartTime = null;
                        _reconnectAttempt = 0;
                        _reconnectDelay = 0;
                    }
                }
            }
            finally { _nativeLifecycle.Release(); }
        }
        catch (Exception ex)
        {
            lock (_connectionLock)
            {
                if (generation == _connectionGeneration)
                {
                    _connectedState = "disconnected";
                    _connectionStartTime = null;
                    Volatile.Write(ref _lastError, ex.Message);
                }
            }
        }
    }

    public async Task<GenericResponse> StopWireGuardAsync()
    {
        VpnServiceReply serviceReply = await VpnServiceClient.SendCommandAsync("STOP_WIREGUARD");
        if (serviceReply.Available)
        {
            return serviceReply.Success
                ? new GenericResponse { Success = true, Message = "WireGuard đã ngắt kết nối qua 292VPN Service." }
                : new GenericResponse { Success = false, Message = "292VPN Service không thể dừng WireGuard." };
        }

        string executable = GetWireGuardExecutablePath();
        var tunnelBaseNames = GetManagedTunnelBaseNames();
        if (!File.Exists(executable) || tunnelBaseNames.Count == 0)
        {
            return new GenericResponse { Success = true, Message = "WireGuard đã ngắt kết nối." };
        }
        int lastExitCode = 0;
        bool timedOut = false;
        foreach (string baseName in tunnelBaseNames)
        {
            var stop = await RunProcessWithTimeoutAsync(executable, "/uninstalltunnelservice " + baseName, 15000);
            if (!stop.Completed) { timedOut = true; continue; }
            if (stop.ExitCode != 0) lastExitCode = stop.ExitCode;
        }
        return lastExitCode == 0 && !timedOut
            ? new GenericResponse { Success = true, Message = "WireGuard đã ngắt kết nối." }
            : new GenericResponse
            {
                Success = false,
                Message = timedOut ? "Dừng WireGuard quá thời gian chờ." : $"Không thể dừng WireGuard (mã {lastExitCode})."
            };
    }

    public async Task<WfpPolicyStatus> GetWfpPolicyStatusAsync()
    {
        VpnServiceReply reply = await VpnServiceClient.SendAsync("WFP_STATUS", 1500);
        if (!reply.Available || !reply.Success || reply.Fields.Length < 7)
        {
            return new WfpPolicyStatus
            {
                ServiceAvailable = reply.Available,
                Message = reply.Available
                    ? "292VPN Service không trả trạng thái WFP hợp lệ."
                    : "292VPN Service chưa khả dụng."
            };
        }

        int.TryParse(reply.Fields[4], out int filterCount);
        bool prepared = reply.Fields[2] == "prepared" || reply.Fields[2] == "enabled";
        bool available = reply.Fields[1] == "available";
        string error = reply.Fields[6] == "none" ? string.Empty : reply.Fields[6];
        return new WfpPolicyStatus
        {
            ServiceAvailable = true,
            WfpAvailable = available,
            Prepared = prepared,
            Dynamic = reply.Fields[3] == "dynamic",
            FilterCount = filterCount,
            EnforcementReady = reply.Fields[5] == "enforcement_ready",
            Error = error,
            Message = !available
                ? error.Length > 0
                    ? "WFP/BFE chưa khả dụng (" + error + ")."
                    : "WFP/BFE chưa được kiểm tra."
                : reply.Fields[2] == "enabled"
                ? "WFP kill switch đang bảo vệ kết nối WireGuard."
                : prepared
                ? "WFP dynamic session đã sẵn sàng; chưa cài filter hoặc kill switch."
                : "WFP policy đang tắt; chưa cài filter hoặc kill switch."
        };
    }

    public async Task<GenericResponse> PrepareWfpPolicyAsync()
    {
        VpnServiceReply reply = await VpnServiceClient.SendAsync("WFP_PREPARE", 5000);
        bool prepared = reply.Success && reply.Fields.Length >= 7 && reply.Fields[2] == "prepared";
        return reply.Available && prepared
            ? new GenericResponse { Success = true, Message = "Đã mở WFP dynamic session không chứa filter." }
            : new GenericResponse
            {
                Success = false,
                Message = "Không thể chuẩn bị WFP dynamic session" + FormatServiceError(reply) + "."
            };
    }

    public async Task<GenericResponse> DisableWfpPolicyAsync()
    {
        VpnServiceReply reply = await VpnServiceClient.SendAsync("WFP_DISABLE", 5000);
        bool disabled = reply.Success && reply.Fields.Length >= 7 && reply.Fields[2] == "disabled";
        return reply.Available && disabled
            ? new GenericResponse { Success = true, Message = "WFP dynamic session đã đóng." }
            : new GenericResponse
            {
                Success = false,
                Message = "Không thể đóng WFP dynamic session" + FormatServiceError(reply) + "."
            };
    }

    private static string FormatServiceError(VpnServiceReply reply)
    {
        if (!reply.Available) return ": service không khả dụng";
        if (reply.Fields.Length < 2) return ": phản hồi không hợp lệ";
        return ": " + string.Join("/", reply.Fields.Skip(1));
    }

    public async Task<GenericResponse?> SaveProxyAsync(Proxy proxy)
    {
        NormalizeManagedProxyName(proxy);
        UpdateConfig(config =>
        {
            if (string.IsNullOrEmpty(proxy.Id))
            {
                proxy.Id = Guid.NewGuid().ToString();
                config.SavedProxies.Add(proxy);
            }
            else
            {
                var existing = config.SavedProxies.FirstOrDefault(p => p.Id == proxy.Id);
                if (existing != null)
                {
                    existing.Name = proxy.Name;
                    existing.Ip = proxy.Ip;
                    existing.Port = proxy.Port;
                    existing.User = proxy.User;
                    existing.Pass = proxy.Pass;
                    existing.Type = proxy.Type;
                }
                else
                {
                    config.SavedProxies.Add(proxy);
                }
            }

            if (string.IsNullOrEmpty(config.ActiveProxyId)) config.ActiveProxyId = proxy.Id;
        });
        return new GenericResponse { Success = true };
    }

    public async Task<GenericResponse?> DeleteProxyAsync(string id)
    {
        UpdateConfig(config =>
        {
            config.SavedProxies.RemoveAll(p => p.Id == id);
            if (config.ActiveProxyId == id)
            {
                config.ActiveProxyId = config.SavedProxies.FirstOrDefault()?.Id ?? string.Empty;
            }
        });
        return new GenericResponse { Success = true };
    }

    public async Task<GenericResponse?> SetActiveProxyAsync(string id)
    {
        bool found = false;
        UpdateConfig(config =>
        {
            found = config.SavedProxies.Any(proxy => proxy.Id == id);
            if (found) config.ActiveProxyId = id;
        });
        return found
            ? new GenericResponse { Success = true }
            : new GenericResponse { Success = false, Message = "Không tìm thấy máy chủ đã chọn." };
    }

    private static void NormalizeManagedProxyNames(IEnumerable<Proxy> proxies)
    {
        foreach (var proxy in proxies) NormalizeManagedProxyName(proxy);
    }

    private static void NormalizeManagedProxyName(Proxy proxy)
    {
        if (string.Equals(proxy.Id, "managed-vn-hanoi-1", StringComparison.OrdinalIgnoreCase))
            proxy.Name = "VN - Hà Nội 1 (VS)";
        else if (string.Equals(proxy.Id, "managed-vn-hanoi-2", StringComparison.OrdinalIgnoreCase))
            proxy.Name = "VN - Hà Nội 2 (HY)";
        else if (string.Equals(proxy.Id, "managed-vn-hanoi-3", StringComparison.OrdinalIgnoreCase))
        {
            proxy.Name = "VN - Hà Nội 3 (WG)";
            proxy.Type = "WireGuard";
        }
        else if (string.Equals(proxy.Id, "managed-vn-hcm-1", StringComparison.OrdinalIgnoreCase))
        {
            proxy.Name = "VN - HCM (WG)";
            proxy.Type = "WireGuard";
        }
        else if (string.Equals(proxy.Id, "managed-sg-wg-1", StringComparison.OrdinalIgnoreCase))
        {
            proxy.Name = "SG - Singapore (WG)";
            proxy.Type = "WireGuard";
        }
        else if (string.Equals(proxy.Id, "managed-hk-wg-1", StringComparison.OrdinalIgnoreCase))
        {
            proxy.Name = "HK - Hong Kong (WG)";
            proxy.Type = "WireGuard";
        }
    }

    public async Task<GenericResponse?> SaveSettingsAsync(int localPort)
    {
        UpdateConfig(config => config.LocalPort = localPort);
        return new GenericResponse { Success = true };
    }

    public async Task<GenericResponse?> SaveProcessRulesAsync(string mode, List<string> rules)
    {
        string normalizedMode = mode == "selected_only" || mode == "bypass_selected" ? mode : "all";
        List<string> normalizedRules = rules
            .SelectMany(p => p.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            .Select(p => p.Trim())
            .Where(p => !string.IsNullOrEmpty(p))
            .Select(p => Path.IsPathRooted(p) ? Path.GetFullPath(p) : Path.GetFileName(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        UpdateConfig(config =>
        {
            config.ProxyMode = normalizedMode;
            config.AllowedProcesses = normalizedRules;
        });

        if (_connectedState != "disconnected")
        {
            await DisconnectAsync();
            return await ConnectAsync();
        }

        return new GenericResponse { Success = true };
    }

    public async Task<GenericResponse?> SaveThemeAsync(string theme)
    {
        UpdateConfig(config => config.Theme = theme);
        return new GenericResponse { Success = true };
    }

    public async Task<GenericResponse?> SaveVpnModeAsync(bool useVpnMode)
    {
        UpdateConfig(config => config.UseVpnMode = useVpnMode);

        if (_connectedState == "connected")
        {
            await DisconnectAsync();
            return await ConnectAsync();
        }

        return new GenericResponse { Success = true };
    }

    public async Task<GenericResponse?> SaveStartOnBootAsync(bool startOnBoot)
    {
        string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "";
        string taskName = "292VPN_Startup";
        if (string.IsNullOrEmpty(exePath))
        {
            return new GenericResponse { Success = false, Message = "Không xác định được đường dẫn ứng dụng." };
        }

        string arguments = startOnBoot
            ? $"/Create /TN \"{taskName}\" /TR \"\\\"{exePath}\\\"\" /SC ONLOGON /RL HIGHEST /F"
            : $"/Delete /TN \"{taskName}\" /F";
        var result = await RunProcessWithTimeoutAsync("schtasks.exe", arguments, 10000);
        if (!startOnBoot && result.Completed && result.ExitCode != 0)
        {
            var query = await RunProcessWithTimeoutAsync("schtasks.exe", $"/Query /TN \"{taskName}\"", 10000);
            if (query.Completed && query.ExitCode != 0)
            {
                result = new ProcessResult { Completed = true, ExitCode = 0 };
            }
        }
        if (!result.Completed || result.ExitCode != 0)
        {
            return new GenericResponse
            {
                Success = false,
                Message = result.Completed ? $"schtasks thất bại (mã {result.ExitCode})." : "schtasks quá thời gian chờ."
            };
        }

        try
        {
            using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
            {
                key?.DeleteValue("292VPN", false);
                key?.DeleteValue("292VPN_srv", false);
            }
        }
        catch (Exception ex) { Debug.WriteLine($"Failed to clean legacy startup keys: {ex.Message}"); }

        UpdateConfig(config => config.StartOnBoot = startOnBoot);
        return new GenericResponse { Success = true };
    }

    public async Task<GenericResponse?> TestProxyAsync(Proxy proxy)
    {
        var test = await TestProxySpeedAsync(proxy.Ip, proxy.Port, proxy.Type, proxy.User, proxy.Pass);
        return new GenericResponse
        {
            Success = test.Success,
            Message = test.Success ? $"{test.Latency}" : test.Message,
            Latency = test.Latency
        };
    }

    public async Task<byte[]?> DownloadBatAsync(string id)
    {
        var config = LoadConfig();
        var proxy = config.SavedProxies.FirstOrDefault(p => p.Id == id);
        if (proxy == null) return null;

        try
        {
            string batContent = Build292ProxyBat(proxy, config.LocalPort);
            return System.Text.Encoding.UTF8.GetBytes(batContent);
        }
        catch
        {
            return null;
        }
    }

    // ==========================================
    // BACKEND HELPER METHODS
    // ==========================================

    private static string GenerateSecret()
    {
        byte[] buffer = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(buffer);
        }
        return Convert.ToBase64String(buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static bool HasTunInterface(string interfaceName)
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces().Any(adapter =>
                adapter.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    private sealed class ProcessResult
    {
        public bool Completed { get; set; }
        public int ExitCode { get; set; } = -1;
    }

    private static async Task<ProcessResult> RunProcessWithTimeoutAsync(string fileName, string arguments, int timeoutMs)
    {
        using (var process = Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            CreateNoWindow = true,
            UseShellExecute = false,
            WindowStyle = ProcessWindowStyle.Hidden
        }))
        {
            if (process == null) return new ProcessResult();
            Task waitTask = Task.Run(() => process.WaitForExit());
            if (await Task.WhenAny(waitTask, Task.Delay(timeoutMs)) != waitTask)
            {
                try { process.Kill(); } catch {}
                return new ProcessResult();
            }
            return new ProcessResult { Completed = true, ExitCode = process.ExitCode };
        }
    }
    
    private static void StopOwnedProcess(Process? process, bool dispose = true)
    {
        if (process == null) return;
        try
        {
            if (!process.HasExited)
            {
                process.Kill();
                process.WaitForExit(3000);
            }
        }
        catch {}
        finally
        {
            if (dispose) process.Dispose();
        }
    }

    private static bool IsProcessRunning(Process? process)
    {
        if (process == null) return false;
        try { return !process.HasExited; }
        catch { return false; }
    }

    private static void VerifyThirdPartyFiles()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string manifestPath = Path.Combine(baseDir, "third_party_manifest.json");
        if (!File.Exists(manifestPath))
        {
            throw new InvalidDataException("Thiếu third_party_manifest.json.");
        }

        using (JsonDocument manifest = JsonDocument.Parse(File.ReadAllText(manifestPath)))
        {
            VerifyFileHash(manifest.RootElement, "sing-box.exe", Path.Combine(baseDir, "sing-box.exe"));
            VerifyFileHash(manifest.RootElement, "wintun.dll", Path.Combine(baseDir, "wintun.dll"));
            VerifyFileHash(manifest.RootElement, "libcronet.dll", Path.Combine(baseDir, "libcronet.dll"));
        }
    }

    private static void VerifyFileHash(JsonElement manifest, string fileName, string filePath)
    {
        if (!File.Exists(filePath)) throw new FileNotFoundException("Thiếu thành phần bắt buộc.", fileName);

        string? expected = FindManifestHash(manifest, fileName);
        if (string.IsNullOrWhiteSpace(expected))
        {
            throw new InvalidDataException($"Manifest không có SHA-256 cho {fileName}.");
        }

        using (var stream = File.OpenRead(filePath))
        using (var sha256 = SHA256.Create())
        {
            string actual = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "");
            if (!actual.Equals(expected!.Replace("-", "").Trim(), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"Kiểm tra toàn vẹn {fileName} thất bại.");
            }
        }
    }

    private static string? FindManifestHash(JsonElement element, string fileName)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (property.Name.Equals(fileName, StringComparison.OrdinalIgnoreCase))
                {
                    if (property.Value.ValueKind == JsonValueKind.String) return property.Value.GetString();
                    if (property.Value.ValueKind == JsonValueKind.Object)
                    {
                        foreach (JsonProperty hashProperty in property.Value.EnumerateObject())
                        {
                            if ((hashProperty.Name.Equals("sha256", StringComparison.OrdinalIgnoreCase) ||
                                 hashProperty.Name.Equals("hash", StringComparison.OrdinalIgnoreCase)) &&
                                hashProperty.Value.ValueKind == JsonValueKind.String)
                            {
                                return hashProperty.Value.GetString();
                            }
                        }
                    }
                }

                string? nested = FindManifestHash(property.Value, fileName);
                if (nested != null) return nested;
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object &&
                    TryGetManifestFileName(item, out string manifestFileName) &&
                    manifestFileName.Equals(fileName, StringComparison.OrdinalIgnoreCase))
                {
                    if (item.TryGetProperty("sha256", out JsonElement hash) && hash.ValueKind == JsonValueKind.String)
                    {
                        return hash.GetString();
                    }
                }
                string? nested = FindManifestHash(item, fileName);
                if (nested != null) return nested;
            }
        }
        return null;
    }

    private static bool TryGetManifestFileName(JsonElement item, out string manifestFileName)
    {
        foreach (string propertyName in new[] { "file", "path" })
        {
            if (item.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.String)
            {
                manifestFileName = Path.GetFileName(value.GetString());
                return !string.IsNullOrEmpty(manifestFileName);
            }
        }

        manifestFileName = string.Empty;
        return false;
    }

    private async Task<ProxyTestResult> TestProxySpeedAsync(string ip, int port, string type, string user, string pass)
    {
        string host = ip;
        int targetPort = port;

        if (type.Equals("URL", StringComparison.OrdinalIgnoreCase))
        {
            var parsed = ParseProxyUrlToOutbound(ip) as Dictionary<string, object>;
            if (parsed != null)
            {
                host = parsed.ContainsKey("server") ? parsed["server"].ToString() ?? "" : "";
                if (parsed.ContainsKey("server_port") && int.TryParse(parsed["server_port"].ToString(), out int p))
                {
                    targetPort = p;
                }
            }
        }

        if (string.IsNullOrEmpty(host))
        {
            return new ProxyTestResult { Success = false, Message = "Invalid address" };
        }

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            using (var client = new System.Net.Sockets.TcpClient())
            {
                var connectTask = client.ConnectAsync(host, targetPort);
                if (await Task.WhenAny(connectTask, Task.Delay(3000)) == connectTask)
                {
                    await connectTask;
                    stopwatch.Stop();
                    return new ProxyTestResult { Success = true, Latency = (int)stopwatch.ElapsedMilliseconds, Ip = host, Message = "OK" };
                }
                return new ProxyTestResult { Success = false, Message = "Timeout" };
            }
        }
        catch (Exception ex)
        {
            return new ProxyTestResult { Success = false, Message = ex.Message };
        }
    }

    private async Task<ProxyTestResult> CheckConnectionThroughProxyAsync(bool useVpnMode, int localPort, CancellationToken cancellationToken)
    {
        using (var probeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            var pending = ProbeUrls
                .Select(url => ProbeUrlAsync(url, useVpnMode, localPort, probeCts.Token))
                .ToList();
            string lastError = "No response";
            Task timeoutTask = Task.Delay(ProbeTimeout, cancellationToken);

            while (pending.Count > 0)
            {
                Task completedTask = await Task.WhenAny(pending.Cast<Task>().Append(timeoutTask));
                cancellationToken.ThrowIfCancellationRequested();
                if (ReferenceEquals(completedTask, timeoutTask))
                {
                    probeCts.Cancel();
                    return new ProxyTestResult { Success = false, Message = lastError == "No response" ? "Timeout" : lastError };
                }

                Task<ProxyTestResult> completed = (Task<ProxyTestResult>)completedTask;
                pending.Remove(completed);
                ProxyTestResult result = await completed;
                if (result.Success)
                {
                    probeCts.Cancel();
                    return result;
                }
                if (lastError == "No response" || string.Equals(lastError, "Timeout", StringComparison.OrdinalIgnoreCase))
                {
                    lastError = result.Message;
                }
            }

            return new ProxyTestResult { Success = false, Message = lastError };
        }
    }

    private static string GetWireGuardExecutablePath()
    {
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wireguard.exe");
    }

    private static string GetWireGuardCliPath()
    {
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wg.exe");
    }

    private static bool IsWireGuardProxy(Proxy? proxy)
    {
        return proxy != null && string.Equals(proxy.Type, "WireGuard", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetWireGuardNodeId(Proxy? proxy)
    {
        const string managedPrefix = "managed-";
        if (proxy?.Id == null || !proxy.Id.StartsWith(managedPrefix, StringComparison.OrdinalIgnoreCase)) return string.Empty;
        string nodeId = proxy.Id.Substring(managedPrefix.Length).ToLowerInvariant();
        return AppPaths.IsValidWireGuardNodeId(nodeId) ? nodeId : string.Empty;
    }

    private static bool IsWireGuardTunnelRunning(string tunnelBaseName)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT State FROM Win32_Service WHERE Name='WireGuardTunnel$" + tunnelBaseName + "'");
            foreach (System.Management.ManagementObject service in searcher.Get())
            {
                return string.Equals(Convert.ToString(service["State"]), "Running", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch (Exception ex) { Debug.WriteLine($"WireGuard service query failed: {ex.Message}"); }
        return false;
    }

    private static List<string> GetManagedTunnelBaseNames()
    {
        var baseNames = new List<string>();
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT Name FROM Win32_Service WHERE Name LIKE 'WireGuardTunnel$292vpn-client%'");
            foreach (System.Management.ManagementObject service in searcher.Get())
            {
                string name = Convert.ToString(service["Name"]) ?? string.Empty;
                if (name.StartsWith("WireGuardTunnel$", StringComparison.Ordinal))
                    baseNames.Add(name.Substring("WireGuardTunnel$".Length));
            }
        }
        catch {}
        return baseNames;
    }

    private static bool AnyManagedTunnelRunning() =>
        GetManagedTunnelBaseNames().Any(IsWireGuardTunnelRunning);

    private static bool HasAnyManagedWireGuardInterface()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces().Any(adapter =>
                adapter.Name.StartsWith("292vpn-client", StringComparison.OrdinalIgnoreCase) &&
                adapter.OperationalStatus == OperationalStatus.Up);
        }
        catch { return false; }
    }

    private static bool HasWireGuardInterface(string adapterName)
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces().Any(adapter =>
                adapter.Name.Equals(adapterName, StringComparison.OrdinalIgnoreCase) &&
                adapter.OperationalStatus == OperationalStatus.Up);
        }
        catch { return false; }
    }

    private static (long Download, long Upload) GetWireGuardTrafficTotals(string adapterName)
    {
        try
        {
            NetworkInterface? adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(candidate =>
                candidate.Name.Equals(adapterName, StringComparison.OrdinalIgnoreCase));
            if (adapter == null) return (0, 0);
            IPv4InterfaceStatistics statistics = adapter.GetIPv4Statistics();
            return (statistics.BytesReceived, statistics.BytesSent);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"WireGuard traffic query failed: {ex.Message}");
            return (0, 0);
        }
    }

    private static List<ConnectionInfo> GetWireGuardConnections()
    {
        var connections = new List<ConnectionInfo>();
        AddTcpConnections(connections);
        AddUdpConnections(connections);
        return connections
            .OrderBy(connection => connection.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(connection => connection.Dest, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void AddTcpConnections(List<ConnectionInfo> connections)
    {
        const int addressFamilyInet = 2;
        const uint insufficientBuffer = 122;
        int size = 0;
        uint result = GetExtendedTcpTable(IntPtr.Zero, ref size, true, addressFamilyInet, TcpTableClass.OwnerPidAll, 0);
        if (result != insufficientBuffer || size <= 0) return;

        IntPtr table = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(table, ref size, true, addressFamilyInet, TcpTableClass.OwnerPidAll, 0) != 0) return;
            int count = Marshal.ReadInt32(table);
            int rowSize = Marshal.SizeOf<TcpRowOwnerPid>();
            IntPtr rowPointer = IntPtr.Add(table, sizeof(int));
            for (int index = 0; index < count; index++)
            {
                TcpRowOwnerPid row = Marshal.PtrToStructure<TcpRowOwnerPid>(IntPtr.Add(rowPointer, index * rowSize));
                if (row.OwningPid == 0 || row.RemoteAddress == 0 || row.RemotePort == 0) continue;
                var remoteAddress = new IPAddress(row.RemoteAddress);
                if (IPAddress.IsLoopback(remoteAddress)) continue;
                connections.Add(CreateConnectionInfo(
                    (int)row.OwningPid,
                    $"TCP {remoteAddress}:{ConvertNetworkPort(row.RemotePort)}"));
            }
        }
        catch (Exception ex) { Debug.WriteLine($"TCP owner table query failed: {ex.Message}"); }
        finally { Marshal.FreeHGlobal(table); }
    }

    private static void AddUdpConnections(List<ConnectionInfo> connections)
    {
        const int addressFamilyInet = 2;
        const uint insufficientBuffer = 122;
        int size = 0;
        uint result = GetExtendedUdpTable(IntPtr.Zero, ref size, true, addressFamilyInet, UdpTableClass.OwnerPid, 0);
        if (result != insufficientBuffer || size <= 0) return;

        IntPtr table = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(table, ref size, true, addressFamilyInet, UdpTableClass.OwnerPid, 0) != 0) return;
            int count = Marshal.ReadInt32(table);
            int rowSize = Marshal.SizeOf<UdpRowOwnerPid>();
            IntPtr rowPointer = IntPtr.Add(table, sizeof(int));
            for (int index = 0; index < count; index++)
            {
                UdpRowOwnerPid row = Marshal.PtrToStructure<UdpRowOwnerPid>(IntPtr.Add(rowPointer, index * rowSize));
                if (row.OwningPid == 0 || row.LocalPort == 0) continue;
                connections.Add(CreateConnectionInfo(
                    (int)row.OwningPid,
                    $"UDP local {new IPAddress(row.LocalAddress)}:{ConvertNetworkPort(row.LocalPort)}"));
            }
        }
        catch (Exception ex) { Debug.WriteLine($"UDP owner table query failed: {ex.Message}"); }
        finally { Marshal.FreeHGlobal(table); }
    }

    private static ConnectionInfo CreateConnectionInfo(int processId, string destination)
    {
        string name = $"PID {processId}";
        string path = string.Empty;
        try
        {
            using Process process = Process.GetProcessById(processId);
            name = process.ProcessName + ".exe";
            TryGetProcessPath(processId, out path);
        }
        catch {}

        return new ConnectionInfo
        {
            Id = $"wireguard-{processId}-{destination}",
            Pid = processId,
            Name = name,
            Path = path,
            Dest = destination,
            Route = "WireGuard",
            Sent = 0,
            Recv = 0,
            Status = "Active",
            Time = DateTime.Now.ToString("HH:mm:ss")
        };
    }

    private static int ConvertNetworkPort(uint value)
    {
        return unchecked((ushort)IPAddress.NetworkToHostOrder((short)value));
    }

    public static void StopBundledSingBoxProcesses()
    {
        string bundledPath = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "sing-box.exe"));
        foreach (Process process in Process.GetProcessesByName("sing-box"))
        {
            try
            {
                if (TryGetProcessPath(process.Id, out string processPath) &&
                    string.Equals(Path.GetFullPath(processPath), bundledPath, StringComparison.OrdinalIgnoreCase))
                {
                    StopOwnedProcess(process, false);
                }
            }
            catch {}
            finally
            {
                process.Dispose();
            }
        }
        DeleteRuntimeSingBoxConfig();
    }

    private static bool TryGetProcessPath(int processId, out string path)
    {
        const uint ProcessQueryLimitedInformation = 0x1000;
        path = string.Empty;
        IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (handle == IntPtr.Zero) return false;
        try
        {
            var buffer = new StringBuilder(32768);
            int size = buffer.Capacity;
            if (!QueryFullProcessImageName(handle, 0, buffer, ref size)) return false;
            path = buffer.ToString();
            return path.Length > 0;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static void AppendBoundedSingBoxLog(string path, string line)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(line + Environment.NewLine);
        if (bytes.LongLength > MaxSingBoxLogBytes) return;
        lock (_singBoxLogLock)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
                if (stream.Length + bytes.Length > MaxSingBoxLogBytes)
                {
                    stream.SetLength(0);
                }
                stream.Position = stream.Length;
                stream.Write(bytes, 0, bytes.Length);
            }
            catch (IOException) {}
            catch (UnauthorizedAccessException) {}
        }
    }

    private static async Task<ProxyTestResult> ProbeUrlAsync(
        string url,
        bool useVpnMode,
        int localPort,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            using (var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            using (var handler = CreateProbeHandler(useVpnMode, localPort))
            using (var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan })
            {
                timeoutCts.CancelAfter(ProbeTimeout);
                using (var response = await client.GetAsync(url, timeoutCts.Token))
                {
                    // Any HTTP response proves that the tunnel transmitted data;
                    // redirects and access-denied responses are valid here.
                }
                return new ProxyTestResult
                {
                    Success = true,
                    Latency = (int)stopwatch.ElapsedMilliseconds,
                    Message = "OK"
                };
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new ProxyTestResult { Success = false, Message = "Timeout" };
        }
        catch (OperationCanceledException)
        {
            return new ProxyTestResult { Success = false, Message = "Cancelled" };
        }
        catch (Exception ex)
        {
            return new ProxyTestResult { Success = false, Message = ex.Message };
        }
    }

    private static HttpClientHandler CreateProbeHandler(bool useVpnMode, int localPort)
    {
        var handler = new HttpClientHandler
        {
            UseProxy = !useVpnMode,
            AllowAutoRedirect = false
        };
        if (!useVpnMode)
        {
            handler.Proxy = new WebProxy($"http://127.0.0.1:{localPort}");
        }
        return handler;
    }

    private static async Task UpdatePublicIpAsync(
        Process process,
        bool useVpnMode,
        int localPort,
        int generation,
        CancellationToken cancellationToken)
    {
        try
        {
            using (var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            using (var handler = CreateProbeHandler(useVpnMode, localPort))
            using (var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan })
            {
                timeoutCts.CancelAfter(ProbeTimeout);
                using (var response = await client.GetAsync("https://api.ipify.org", timeoutCts.Token))
                {
                    response.EnsureSuccessStatusCode();
                    string publicIp = (await response.Content.ReadAsStringAsync()).Trim();
                    if (!IPAddress.TryParse(publicIp, out _)) return;

                    lock (_connectionLock)
                    {
                        if (generation == _connectionGeneration &&
                            ReferenceEquals(_singBoxProcess, process) &&
                            _connectedState == "connected")
                        {
                            _currentPublicIp = publicIp;
                        }
                    }
                }
            }
        }
        catch
        {
            // Public IP is informational and must never delay or fail readiness.
        }
    }

    private static Dictionary<string, string> ParseQueryString(string query)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query)) return dict;
        
        query = query.TrimStart('?');
        string[] pairs = query.Split('&');
        foreach (string pair in pairs)
        {
            string[] parts = pair.Split('=');
            if (parts.Length > 0)
            {
                string key = Uri.UnescapeDataString(parts[0]);
                string val = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]) : "";
                dict[key] = val;
            }
        }
        return dict;
    }

    private object ParseProxyUrlToOutbound(string urlStr)
    {
        try
        {
            urlStr = urlStr.Trim();
            var uri = new Uri(urlStr);
            string scheme = uri.Scheme.ToLower();

            var result = new Dictionary<string, object>
            {
                { "type", scheme },
                { "server", uri.Host },
                { "server_port", uri.Port }
            };

            string tag = "proxy-out";
            if (!string.IsNullOrEmpty(uri.Fragment))
            {
                tag = Uri.UnescapeDataString(uri.Fragment.TrimStart('#'));
            }
            result["tag"] = tag;

            if (scheme == "vless")
            {
                var queryParams = ParseQueryString(uri.Query);
                result["uuid"] = Uri.UnescapeDataString(uri.UserInfo);

                // Do not force XUDP for every VLESS server. XUDP is a server/client
                // compatibility option; forcing it breaks UDP applications when
                // the Xray inbound was not configured for the same packet mode.
                // Honor it only when the supplied VLESS URI explicitly requests it.
                // VLESS share links spell this "packetEncoding"; some panels emit the
                // snake_case form. OrdinalIgnoreCase does not bridge the underscore,
                // so both spellings must be accepted - otherwise the server's
                // requested packet mode is silently dropped and UDP fails while TCP
                // still works.
                string packetEncoding = queryParams.ContainsKey("packetEncoding") ? queryParams["packetEncoding"] : "";
                if (string.IsNullOrWhiteSpace(packetEncoding) && queryParams.ContainsKey("packet_encoding"))
                {
                    packetEncoding = queryParams["packet_encoding"];
                }

                // sing-box accepts only the exact lowercase values "packetaddr" or
                // "xudp". Anything else - including the "none" some panels emit, or a
                // differently cased value - makes the whole config fail to load and
                // takes the entire VPN down. Normalize and whitelist; otherwise omit
                // the field so sing-box applies its own default.
                packetEncoding = packetEncoding.Trim().ToLowerInvariant();
                if (packetEncoding == "packetaddr" || packetEncoding == "xudp")
                {
                    result["packet_encoding"] = packetEncoding;
                }

                string flow = queryParams.ContainsKey("flow") ? queryParams["flow"] : "";
                if (!string.IsNullOrEmpty(flow))
                {
                    result["flow"] = flow;
                }

                string security = queryParams.ContainsKey("security") ? queryParams["security"].ToLower() : "";
                string pbk = queryParams.ContainsKey("pbk") ? queryParams["pbk"] : "";
                string sni = queryParams.ContainsKey("sni") ? queryParams["sni"] : "";
                string fp = queryParams.ContainsKey("fp") ? queryParams["fp"] : "";
                string sid = queryParams.ContainsKey("sid") ? queryParams["sid"] : "";

                if (security == "tls" || security == "reality" || !string.IsNullOrEmpty(pbk) || !string.IsNullOrEmpty(sni))
                {
                    bool isReality = security == "reality" || !string.IsNullOrEmpty(pbk);
                    var tlsConfig = new Dictionary<string, object> { { "enabled", true } };
                    // An absent sni breaks REALITY outright; fall back to the host
                    // like the trojan branch does.
                    tlsConfig["server_name"] = !string.IsNullOrEmpty(sni) ? sni : uri.Host;
                    // Without uTLS the ClientHello carries Go's TLS signature, which
                    // DPI in restrictive regions matches on. REALITY always needs a
                    // browser fingerprint, so default it when the URL omits fp.
                    if (!string.IsNullOrEmpty(fp) || isReality)
                    {
                        tlsConfig["utls"] = new Dictionary<string, object>
                        {
                            { "enabled", true },
                            { "fingerprint", !string.IsNullOrEmpty(fp) ? fp : "chrome" }
                        };
                    }
                    string alpn = queryParams.ContainsKey("alpn") ? queryParams["alpn"] : "";
                    // REALITY negotiates its own alpn; setting it explicitly breaks the handshake.
                    if (!string.IsNullOrEmpty(alpn) && !isReality)
                    {
                        tlsConfig["alpn"] = Uri.UnescapeDataString(alpn)
                            .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                            .Select(a => a.Trim())
                            .Where(a => a.Length > 0)
                            .ToArray();
                    }
                    if (isReality)
                    {
                        tlsConfig["reality"] = new Dictionary<string, object>
                        {
                            { "enabled", true },
                            { "public_key", pbk },
                            { "short_id", sid }
                        };
                    }
                    result["tls"] = tlsConfig;
                }

                string transportType = queryParams.ContainsKey("type") ? queryParams["type"].ToLower() : "tcp";
                string path = queryParams.ContainsKey("path") ? queryParams["path"] : "";
                string host = queryParams.ContainsKey("host") ? queryParams["host"] : "";
                string serviceName = queryParams.ContainsKey("servicename") ? queryParams["servicename"] : 
                                     queryParams.ContainsKey("serviceName") ? queryParams["serviceName"] : "";

                if (transportType == "ws" || transportType == "websocket" || transportType == "grpc" || transportType == "http")
                {
                    var transportConfig = new Dictionary<string, object>();
                    if (transportType == "ws" || transportType == "websocket")
                    {
                        transportConfig["type"] = "ws";
                        if (!string.IsNullOrEmpty(path))
                        {
                            transportConfig["path"] = Uri.UnescapeDataString(path);
                        }
                        if (!string.IsNullOrEmpty(host))
                        {
                            transportConfig["headers"] = new Dictionary<string, string> { { "Host", host } };
                        }
                    }
                    else if (transportType == "grpc")
                    {
                        transportConfig["type"] = "grpc";
                        if (!string.IsNullOrEmpty(serviceName))
                        {
                            transportConfig["service_name"] = serviceName;
                        }
                    }
                    else if (transportType == "http")
                    {
                        transportConfig["type"] = "http";
                        if (!string.IsNullOrEmpty(path))
                        {
                            transportConfig["path"] = Uri.UnescapeDataString(path);
                        }
                        if (!string.IsNullOrEmpty(host))
                        {
                            transportConfig["host"] = new[] { host };
                        }
                    }
                    result["transport"] = transportConfig;
                }
            }
            else if (scheme == "trojan")
            {
                result["password"] = Uri.UnescapeDataString(uri.UserInfo);

                var queryParams = ParseQueryString(uri.Query);
                var tlsConfig = new Dictionary<string, object> { { "enabled", true } };
                string sni = queryParams.ContainsKey("sni") ? queryParams["sni"] : uri.Host;
                string fp = queryParams.ContainsKey("fp") ? queryParams["fp"] : "";
                if (!string.IsNullOrEmpty(sni))
                {
                    tlsConfig["server_name"] = sni;
                }
                if (!string.IsNullOrEmpty(fp))
                {
                    tlsConfig["utls"] = new Dictionary<string, object>
                    {
                        { "enabled", true },
                        { "fingerprint", fp }
                    };
                }
                result["tls"] = tlsConfig;

                string transportType = queryParams.ContainsKey("type") ? queryParams["type"].ToLower() : "tcp";
                string path = queryParams.ContainsKey("path") ? queryParams["path"] : "";
                string host = queryParams.ContainsKey("host") ? queryParams["host"] : "";
                string serviceName = queryParams.ContainsKey("servicename") ? queryParams["servicename"] :
                                     queryParams.ContainsKey("serviceName") ? queryParams["serviceName"] : "";

                if (transportType == "ws" || transportType == "websocket" || transportType == "grpc" || transportType == "http")
                {
                    var transportConfig = new Dictionary<string, object>();
                    if (transportType == "ws" || transportType == "websocket")
                    {
                        transportConfig["type"] = "ws";
                        if (!string.IsNullOrEmpty(path))
                        {
                            transportConfig["path"] = Uri.UnescapeDataString(path);
                        }
                        if (!string.IsNullOrEmpty(host))
                        {
                            transportConfig["headers"] = new Dictionary<string, string> { { "Host", host } };
                        }
                    }
                    else if (transportType == "grpc")
                    {
                        transportConfig["type"] = "grpc";
                        if (!string.IsNullOrEmpty(serviceName))
                        {
                            transportConfig["service_name"] = serviceName;
                        }
                    }
                    else if (transportType == "http")
                    {
                        transportConfig["type"] = "http";
                        if (!string.IsNullOrEmpty(path))
                        {
                            transportConfig["path"] = Uri.UnescapeDataString(path);
                        }
                        if (!string.IsNullOrEmpty(host))
                        {
                            transportConfig["host"] = new[] { host };
                        }
                    }
                    result["transport"] = transportConfig;
                }
            }
            else if (scheme == "ss")
            {
                string userInfo = uri.UserInfo;
                if (!string.IsNullOrEmpty(userInfo) && userInfo.Contains(":"))
                {
                    string[] authParts = userInfo.Split(new[] { ':' }, 2);
                    result["method"] = Uri.UnescapeDataString(authParts[0]);
                    result["password"] = Uri.UnescapeDataString(authParts[1]);
                }
                else
                {
                    string base64Str = uri.Authority;
                    if (base64Str.Contains("@"))
                    {
                        string[] parts = base64Str.Split(new[] { '@' }, 2);
                        string left = parts[0];
                        string right = parts[1];
                        string decoded = DecodeBase64(left);
                        if (decoded.Contains(":"))
                        {
                            string[] authParts = decoded.Split(new[] { ':' }, 2);
                            result["method"] = authParts[0];
                            result["password"] = authParts[1];
                        }
                        if (right.Contains(":"))
                        {
                            string[] hostParts = right.Split(new[] { ':' }, 2);
                            result["server"] = hostParts[0];
                            result["server_port"] = int.Parse(hostParts[1]);
                        }
                        else
                        {
                            result["server"] = right;
                        }
                    }
                    else
                    {
                        string rawStr = base64Str + uri.PathAndQuery;
                        if (rawStr.Contains("#")) rawStr = rawStr.Split('#')[0];
                        string decoded = DecodeBase64(rawStr);
                        if (decoded.Contains("@"))
                        {
                            string[] parts = decoded.Split(new[] { '@' }, 2);
                            string auth = parts[0];
                            string server = parts[1];
                            if (auth.Contains(":"))
                            {
                                string[] authParts = auth.Split(new[] { ':' }, 2);
                                result["method"] = authParts[0];
                                result["password"] = authParts[1];
                            }
                            if (server.Contains(":"))
                            {
                                string[] serverParts = server.Split(new[] { ':' }, 2);
                                result["server"] = serverParts[0];
                                result["server_port"] = int.Parse(serverParts[1]);
                            }
                            else
                            {
                                result["server"] = server;
                            }
                        }
                    }
                }
                result["type"] = "shadowsocks";
            }
            else if (scheme == "hysteria2" || scheme == "hy2")
            {
                result["type"] = "hysteria2";
                result["password"] = Uri.UnescapeDataString(uri.UserInfo);

                var queryParams = ParseQueryString(uri.Query);

                // Hysteria2 always uses TLS
                var tlsConfig = new Dictionary<string, object> { { "enabled", true } };
                string sni = queryParams.ContainsKey("sni") ? queryParams["sni"] : uri.Host;
                if (!string.IsNullOrEmpty(sni))
                {
                    tlsConfig["server_name"] = sni;
                }

                if (queryParams.ContainsKey("insecure") && queryParams["insecure"] == "1")
                    tlsConfig["insecure"] = true;

                result["tls"] = tlsConfig;

                // Obfuscation password (optional)
                if (queryParams.ContainsKey("obfs") && !string.IsNullOrEmpty(queryParams["obfs"]))
                {
                    result["obfs"] = new Dictionary<string, object>
                    {
                        { "type", "salamander" },
                        { "password", queryParams["obfs"] }
                    };
                }

                // Upload/Download bandwidth (optional, in Mbps)
                if (queryParams.ContainsKey("up") && int.TryParse(queryParams["up"], out int upMbps))
                {
                    result["up_mbps"] = upMbps;
                }
                if (queryParams.ContainsKey("down") && int.TryParse(queryParams["down"], out int downMbps))
                {
                    result["down_mbps"] = downMbps;
                }
            }

            return result;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Không thể phân tích cấu hình proxy URL.", ex);
        }
    }

    private string DecodeBase64(string b64)
    {
        try
        {
            b64 = b64.Trim().Replace(" ", "");
            int pad = b64.Length % 4;
            if (pad > 0) b64 += new string('=', 4 - pad);
            byte[] bytes = Convert.FromBase64String(b64);
            return System.Text.Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return "";
        }
    }

    private string GenerateSingBoxConfig(Proxy activeProxy, AppConfig config, string tunInterfaceName)
    {
        string proxyType = activeProxy.Type.ToUpper();
        object outboundProxy;
        object? wireGuardEndpoint = null;

        if (proxyType == "WIREGUARD")
        {
            wireGuardEndpoint = ParseWireGuardEndpoint(activeProxy);
            outboundProxy = wireGuardEndpoint;
        }
        else if (proxyType == "URL")
        {
            var parsed = ParseProxyUrlToOutbound(activeProxy.Ip);
            if (parsed is Dictionary<string, object> dictProxy)
            {
                dictProxy["tag"] = "proxy-out";
            }
            outboundProxy = parsed;
        }
        else
        {
            string typeLower = proxyType.ToLower();
            if (typeLower == "socks5") typeLower = "socks";

            var socksProxy = new Dictionary<string, object>
            {
                { "type", typeLower },
                { "tag", "proxy-out" },
                { "server", activeProxy.Ip },
                { "server_port", activeProxy.Port }
            };

            if (typeLower == "socks")
            {
                socksProxy["version"] = "5";
            }

            if (!string.IsNullOrEmpty(activeProxy.User) && !string.IsNullOrEmpty(activeProxy.Pass))
            {
                socksProxy["username"] = activeProxy.User;
                socksProxy["password"] = activeProxy.Pass;
            }

            outboundProxy = socksProxy;
        }

        var outboundDirect = new { type = "direct", tag = "direct-out" };

        // sing-box 1.13 removed the special "dns"/"block" outbounds; DNS is
        // handled by the "hijack-dns" rule action below.
        var outboundsList = new List<object>();

        if (wireGuardEndpoint != null)
        {
            outboundsList.Add(outboundDirect);
        }
        else if (config.ProxyMode == "selected_only")
        {
            outboundsList.Add(outboundDirect);
            outboundsList.Add(outboundProxy);
        }
        else
        {
            outboundsList.Add(outboundProxy);
            outboundsList.Add(outboundDirect);
        }

        // sing-box 1.10 merged inet4_address into the address array and 1.13
        // removed legacy inbound sniff fields in favor of the sniff rule action.
        // Keep the TUN IPv4-only because IPv6 may be disabled at the Windows
        // stack level; assigning an IPv6 address then makes sing-box fail at startup.
        var inboundTun = new Dictionary<string, object>
        {
            { "type", "tun" },
            { "tag", "tun-in" },
            { "interface_name", tunInterfaceName },
            { "address", new[] { "172.19.0.1/30" } },
            { "mtu", 1400 },
            { "auto_route", true },
            // Keep strict route disabled for Windows system-stack TUN. Enabling
            // it here can prevent the VLESS transport socket from reaching its
            // endpoint before the route is established, leaving the UI connected
            // while sing-box cannot complete the VLESS handshake.
            { "strict_route", false },
            { "endpoint_independent_nat", true },
            { "stack", "system" }
        };

        var experimental = new
        {
            clash_api = new
            {
                external_controller = ClashApiHost,
                secret = Volatile.Read(ref _clashApiSecret)
            },
            cache_file = new
            {
                enabled = true,
                path = AppPaths.SingBoxCacheFile
            }
        };

        var routeRules = new List<object>
        {
            new { action = "sniff" },
            new { protocol = "dns", action = "hijack-dns" },
            // VoiceProbe measures the call path, so it must take the tunnel even
            // to the node's own IP or its private WireGuard address.
            new { process_name = new[] { VoiceProbeProcessName }, outbound = "proxy-out" },
            new { process_path_regex = ProcessNameRegexes(new[] { VoiceProbeProcessName }), outbound = "proxy-out" },
            new { ip_is_private = true, outbound = "direct-out" }
        };
        if (wireGuardEndpoint != null)
        {
            routeRules.Add(new { inbound = new[] { "local-in" }, outbound = "proxy-out" });
        }
        // The health probe must measure the tunnel. In selected-only mode
        // 292VPN.exe itself is not a selected process, so its TUN probe fell
        // through to direct-out; where the direct path to Cloudflare is filtered
        // (UAE) three failed probes restarted a healthy tunnel mid-call.
        routeRules.Add(new { ip_cidr = ProbeCidrs, network = new[] { "tcp" }, port = new[] { 80 }, outbound = "proxy-out" });

        // In "all" mode every app must still have working networking, so handle
        // the traffic a VLESS tunnel cannot carry or would break:
        //  - Other VPN clients' own control channels and encapsulated traffic go
        //    direct. Their tunnel endpoints are public IPs we must not swallow,
        //    and their virtual gateways are unreachable from inside our TUN.
        //  - QUIC (UDP/443) is rejected, not bypassed. Bypassing would leak the
        //    browser's traffic outside the tunnel, which defeats "all". A reject
        //    makes Chrome fall back to TCP immediately, so the page still loads
        //    and it loads through the tunnel.
        //  - SIP/RTP stays on the tunnel deliberately — that is the point of
        //    routing MicroSIP through it.
        if (config.ProxyMode == "all")
        {
            routeRules.Add(new { process_path_regex = ProcessNameRegexes(OtherVpnProcessFamily), outbound = "direct-out" });
            // Match sniffed QUIC, not every UDP/443 flow: call media and TURN
            // relays (Zalo, WebRTC) also use UDP/443 and would otherwise be
            // forced onto a laggy TCP fallback.
            routeRules.Add(new { protocol = new[] { "quic" }, action = "reject", method = "default" });
        }

        string serverAddr = "";
        if (outboundProxy is Dictionary<string, object> dict)
        {
            serverAddr = dict.ContainsKey("server") ? dict["server"].ToString() ?? "" : "";
        }
        else
        {
            var prop = outboundProxy.GetType().GetProperty("server");
            if (prop != null)
            {
                serverAddr = prop.GetValue(outboundProxy)?.ToString() ?? "";
            }
        }

        if (!string.IsNullOrEmpty(serverAddr))
        {
            bool isIp = System.Net.IPAddress.TryParse(serverAddr, out _);
            if (isIp)
            {
                routeRules.Add(new { ip_cidr = new[] { $"{serverAddr}/32" }, outbound = "direct-out" });
            }
            else
            {
                routeRules.Add(new { domain = new[] { serverAddr }, outbound = "direct-out" });
            }
        }

        string? processOutbound = config.ProxyMode == "selected_only"
            ? "proxy-out"
            : config.ProxyMode == "bypass_selected" ? "direct-out" : null;
        // Process names routed to the tunnel, reused to tunnel their DNS as well.
        var selectedProcessRules = new List<string>();
        var selectedProcessNames = new List<string>();
        bool whatsappSelected = false;
        if (processOutbound != null && config.AllowedProcesses.Count > 0)
        {
            var procPaths = config.AllowedProcesses
                .SelectMany(p => p.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                .Select(p => p.Trim())
                .Where(Path.IsPathRooted)
                .Select(Path.GetFullPath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var procNames = config.AllowedProcesses
                .SelectMany(p => p.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                .Select(p => p.Trim())
                .Where(p => !Path.IsPathRooted(p))
                .Select(Path.GetFileName)
                .Where(p => !string.IsNullOrEmpty(p))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            procPaths.AddRange(FindRunningProcessPaths(procNames));
            procPaths = procPaths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            selectedProcessNames.AddRange(procNames);
            selectedProcessNames.AddRange(
                procPaths.Select(Path.GetFileName).Where(p => !string.IsNullOrEmpty(p))!);
            if (procPaths.Concat(procNames).Any(p =>
                ManagedZaloProcessFamily.Contains(Path.GetFileName(p), StringComparer.OrdinalIgnoreCase)))
            {
                procNames.AddRange(ManagedZaloProcessFamily);
                selectedProcessNames.AddRange(ManagedZaloProcessFamily);
            }
            if (procPaths.Concat(procNames).Any(p =>
                UltraViewerProcessFamily.Contains(Path.GetFileName(p), StringComparer.OrdinalIgnoreCase)))
            {
                procNames.AddRange(UltraViewerProcessFamily);
                selectedProcessNames.AddRange(UltraViewerProcessFamily);
            }
            // Substring match rather than family membership: users type
            // "whatsapp" or "WhatsApp", neither of which equals a real
            // executable name, so an exact lookup silently matches nothing.
            // ProcessNameRegexes below anchors on the basename and therefore
            // covers the versioned WindowsApps path without resolving it.
            if (procPaths.Concat(procNames).Any(p =>
                p.IndexOf("WhatsApp", StringComparison.OrdinalIgnoreCase) >= 0))
            {
                whatsappSelected = true;
                procNames.AddRange(WhatsAppProcessFamily);
                selectedProcessNames.AddRange(WhatsAppProcessFamily);
            }
            selectedProcessNames = selectedProcessNames.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            procNames = ProcessNameRegexes(procNames);
            var procDirectories = ProcessDirectoryRegexes(procPaths);
            if (procPaths.Count > 0)
            {
                routeRules.Add(new { process_path_regex = ProcessPathRegexes(procPaths), outbound = processOutbound });
            }
            if (procDirectories.Count > 0)
            {
                // Multi-process applications commonly launch helpers with other
                // executable names. Matching the installation tree also covers
                // helpers created after the VPN connection has started.
                routeRules.Add(new { process_path_regex = procDirectories, outbound = processOutbound });
            }
            if (selectedProcessNames.Count > 0)
            {
                routeRules.Add(new { process_name = selectedProcessNames, outbound = processOutbound });
            }
            if (procNames.Count > 0)
            {
                routeRules.Add(new { process_path_regex = procNames, outbound = processOutbound });
            }
            selectedProcessRules.AddRange(procNames);
            selectedProcessRules.AddRange(
                ProcessNameRegexes(procPaths.Select(Path.GetFileName).Where(p => !string.IsNullOrEmpty(p))!));
            selectedProcessRules.AddRange(procDirectories);
            selectedProcessRules = selectedProcessRules.Distinct(StringComparer.Ordinal).ToList();
        }

        if (config.ProxyMode == "selected_only")
        {
            // SIP can emit its first UDP packet before Windows reports the owning
            // process. Route standard SIP signaling ports explicitly so the
            // registration request cannot fall through to direct-out.
            routeRules.Add(new { network = new[] { "tcp", "udp" }, port = new[] { 5060, 5061 }, outbound = "proxy-out" });
            var voipNames = VoipProcessFamily.Distinct(StringComparer.Ordinal).ToList();
            routeRules.Add(new { process_name = voipNames, outbound = "proxy-out" });
            routeRules.Add(new { process_path_regex = ProcessNameRegexes(voipNames), outbound = "proxy-out" });
            selectedProcessNames.AddRange(voipNames);
            selectedProcessRules.AddRange(ProcessNameRegexes(voipNames));
        }

        // Zalo is often launched by profile managers (ZaX, ZPool) that set a
        // per-profile Vietnam HTTP proxy. That proxy carries only TCP, so call
        // audio leaves as direct UDP, which UAE blocks, and Zalo falls back to a
        // choppy TCP relay. Tunnel only Zalo's UDP; its TCP keeps using the
        // profile proxy without being nested inside the VPN.
        if (config.ProxyMode == "selected_only")
        {
            routeRules.Add(new { process_name = ManagedZaloProcessFamily, network = new[] { "udp" }, outbound = "proxy-out" });
            routeRules.Add(new { process_path_regex = ProcessNameRegexes(ManagedZaloProcessFamily), network = new[] { "udp" }, outbound = "proxy-out" });
        }

        // A webview's NetworkService is sometimes reported without the parent
        // Zalo process. Domain matching prevents those connections from falling
        // through to direct-out in selected-only mode.
        if (config.ProxyMode == "selected_only")
        {
            routeRules.Add(new { domain_suffix = ZaloDomainSuffixes, outbound = "proxy-out" });
        }

        // Same fallback for WhatsApp's shared WebView2 process.
        if (config.ProxyMode == "selected_only" && whatsappSelected)
        {
            routeRules.Add(new { domain_suffix = WhatsAppDomainSuffixes, outbound = "proxy-out" });
        }

        // Do not rely on outbound order or route.final for split tunneling.
        // This terminal rule guarantees every unmatched process stays direct.
        if (config.ProxyMode == "selected_only")
        {
            routeRules.Add(new { network = new[] { "tcp", "udp" }, outbound = "direct-out" });
        }

        // "dns-bootstrap" must stay direct: it is what resolves the VPN server's
        // own hostname. Routing it through proxy-out would deadlock (the proxy
        // cannot connect until its address resolves, and the resolver cannot
        // answer until the proxy connects). Local system resolvers are also the
        // only ones reachable where public DoH endpoints are filtered.
        //
        // A detour naming a plain "direct" outbound is rejected at startup
        // ("detour to an empty direct outbound makes no sense") even though
        // `sing-box check` accepts it, so omit detour entirely for direct DNS.
        var dnsServers = new List<object>();
        if (config.ProxyMode == "all" || config.ProxyMode == "bypass_selected")
        {
            dnsServers.Add(new { type = "https", tag = "dns-remote", server = "1.1.1.1", detour = "proxy-out" });
            dnsServers.Add(new { type = "https", tag = "dns-fallback", server = "9.9.9.9", detour = "proxy-out" });
        }
        else
        {
            dnsServers.Add(new { type = "https", tag = "dns-remote", server = "1.1.1.1" });
            dnsServers.Add(new { type = "https", tag = "dns-fallback", server = "9.9.9.9" });
        }
        dnsServers.Add(new { type = "local", tag = "dns-bootstrap" });
        // Selected apps must resolve through the tunnel too. Otherwise a filtered
        // or hijacked local resolver breaks them even though their traffic is
        // tunnelled — and their lookups leak to the local network.
        bool tunnelSelectedDns = config.ProxyMode == "selected_only" && selectedProcessRules.Count > 0;
        bool bypassSelectedDns = config.ProxyMode == "bypass_selected" && selectedProcessRules.Count > 0;
        if (tunnelSelectedDns)
        {
            dnsServers.Add(new { type = "https", tag = "dns-selected", server = "1.1.1.1", detour = "proxy-out" });
        }

        var dnsRules = new List<object>();
        if (tunnelSelectedDns)
        {
            dnsRules.Add(new { process_name = selectedProcessNames.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), server = "dns-selected" });
            dnsRules.Add(new { process_path_regex = selectedProcessRules, server = "dns-selected" });
        }
        else if (bypassSelectedDns)
        {
            dnsRules.Add(new { process_name = selectedProcessNames.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), server = "dns-bootstrap" });
            dnsRules.Add(new { process_path_regex = selectedProcessRules, server = "dns-bootstrap" });
        }

        // In split-tunnel mode the TUN hijacks every app's DNS, including apps we
        // route direct. Answering those from a public DoH endpoint makes them
        // depend on 1.1.1.1:443 being reachable, so where that is filtered — UAE
        // and similar — direct apps resolve nothing and look offline even though
        // their TCP path is fine. sing-box does not fail over between servers, so
        // the unreferenced dns-fallback never rescues them. Send them to the local
        // resolver instead: that is exactly what they would use with the VPN off.
        var dnsConfig = new Dictionary<string, object>
        {
            { "servers", dnsServers },
            { "final", config.ProxyMode == "selected_only" ? "dns-bootstrap" : "dns-remote" },
            { "strategy", "ipv4_only" }
        };
        if (dnsRules.Count > 0)
        {
            dnsConfig["rules"] = dnsRules;
        }

        var inbounds = new List<object>();
        if (config.UseVpnMode)
        {
            inbounds.Add(inboundTun);
        }

        // Always add mixed inbound for proxy mode and port-readiness check
        inbounds.Add(new
        {
            type = "mixed",
            tag = "local-in",
            listen = "127.0.0.1",
            listen_port = config.LocalPort
        });

        var singBoxConfig = new Dictionary<string, object>
        {
            ["log"] = new
            {
                level = "info"
            },
            ["dns"] = dnsConfig,
            ["inbounds"] = inbounds,
            ["outbounds"] = outboundsList,
            ["route"] = new
            {
                rules = routeRules,
                final = config.ProxyMode == "selected_only" ? "direct-out" : "proxy-out",
                auto_detect_interface = true,
                find_process = true,
                // sing-box 1.12 requires outbounds that resolve domains to declare
                // a resolver. This must be the direct bootstrap, not dns-remote:
                // proxy-out resolving its own server through itself deadlocks.
                default_domain_resolver = "dns-bootstrap"
            },
            ["experimental"] = experimental
        };
        if (wireGuardEndpoint != null)
        {
            singBoxConfig["endpoints"] = new[] { wireGuardEndpoint };
        }

        return JsonSerializer.Serialize(singBoxConfig, new JsonSerializerOptions { WriteIndented = true });
    }

    private static Dictionary<string, object> ParseWireGuardEndpoint(Proxy activeProxy)
    {
        string nodeId = GetWireGuardNodeId(activeProxy);
        string configPath = AppPaths.WireGuardConfigFile(nodeId);
        if (nodeId.Length > 0 && !File.Exists(configPath) && File.Exists(AppPaths.LegacyWireGuardConfigFile))
        {
            configPath = AppPaths.LegacyWireGuardConfigFile;
        }
        string configText;
        try
        {
            configText = File.ReadAllText(configPath);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Không thể đọc cấu hình WireGuard đã cấp.", ex);
        }

        return ParseWireGuardEndpoint(configText);
    }

    private static Dictionary<string, object> ParseWireGuardEndpoint(string configText)
    {
        var interfaceValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var peerValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string>? section = null;
        int peerCount = 0;
        foreach (string rawLine in configText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal) || line.StartsWith(";", StringComparison.Ordinal)) continue;
            if (line.Equals("[Interface]", StringComparison.OrdinalIgnoreCase))
            {
                section = interfaceValues;
                continue;
            }
            if (line.Equals("[Peer]", StringComparison.OrdinalIgnoreCase))
            {
                peerCount++;
                if (peerCount > 1)
                    throw new InvalidOperationException("Cấu hình nhiều WireGuard peer chưa được hỗ trợ.");
                section = peerValues;
                continue;
            }
            int separator = line.IndexOf('=');
            if (section == null || separator <= 0) continue;
            section[line.Substring(0, separator).Trim()] = line.Substring(separator + 1).Trim();
        }

        string Required(Dictionary<string, string> values, string key)
        {
            if (!values.TryGetValue(key, out string? value) || string.IsNullOrWhiteSpace(value))
                throw new InvalidOperationException($"Cấu hình WireGuard thiếu {key}.");
            return value;
        }

        string endpoint = Required(peerValues, "Endpoint");
        string host;
        string portText;
        if (endpoint.StartsWith("[", StringComparison.Ordinal))
        {
            int closingBracket = endpoint.IndexOf(']');
            if (closingBracket <= 1 || closingBracket + 2 >= endpoint.Length || endpoint[closingBracket + 1] != ':')
                throw new InvalidOperationException("Endpoint WireGuard không hợp lệ.");
            host = endpoint.Substring(1, closingBracket - 1);
            portText = endpoint.Substring(closingBracket + 2);
        }
        else
        {
            int separator = endpoint.LastIndexOf(':');
            if (separator <= 0 || separator == endpoint.Length - 1)
                throw new InvalidOperationException("Endpoint WireGuard không hợp lệ.");
            host = endpoint.Substring(0, separator);
            portText = endpoint.Substring(separator + 1);
        }
        if (!int.TryParse(portText, out int port) || port < 1 || port > 65535)
            throw new InvalidOperationException("Port WireGuard không hợp lệ.");

        int mtu = 1280;
        if (interfaceValues.TryGetValue("MTU", out string? mtuText) &&
            (!int.TryParse(mtuText, out mtu) || mtu < 576 || mtu > 65535))
            throw new InvalidOperationException("MTU WireGuard không hợp lệ.");
        int keepalive = 0;
        if (peerValues.TryGetValue("PersistentKeepalive", out string? keepaliveText) &&
            (!int.TryParse(keepaliveText, out keepalive) || keepalive < 0))
            throw new InvalidOperationException("PersistentKeepalive WireGuard không hợp lệ.");

        var peer = new Dictionary<string, object>
        {
            ["address"] = host,
            ["port"] = port,
            ["public_key"] = Required(peerValues, "PublicKey"),
            ["allowed_ips"] = Required(peerValues, "AllowedIPs")
                .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(value => value.Trim())
                .ToArray(),
            ["persistent_keepalive_interval"] = keepalive
        };
        if (peerValues.TryGetValue("PresharedKey", out string? preSharedKey) && !string.IsNullOrWhiteSpace(preSharedKey))
            peer["pre_shared_key"] = preSharedKey;

        return new Dictionary<string, object>
        {
            ["type"] = "wireguard",
            ["tag"] = "proxy-out",
            ["system"] = false,
            ["mtu"] = mtu,
            ["address"] = Required(interfaceValues, "Address")
                .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(value => value.Trim())
                .ToArray(),
            ["private_key"] = Required(interfaceValues, "PrivateKey"),
            ["peers"] = new[] { peer },
            ["inet4_bind_address"] = GetDefaultPhysicalIPv4Address()
        };
    }

    private static string GetDefaultPhysicalIPv4Address()
    {
        NetworkInterface? adapter = NetworkInterface.GetAllNetworkInterfaces()
            .Where(candidate => candidate.OperationalStatus == OperationalStatus.Up)
            .Where(candidate => candidate.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Where(candidate => !candidate.Name.StartsWith("292vpn", StringComparison.OrdinalIgnoreCase))
            .FirstOrDefault(candidate => candidate.GetIPProperties().GatewayAddresses.Any(gateway =>
                gateway.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                !gateway.Address.Equals(IPAddress.Any)));
        IPAddress? address = adapter?.GetIPProperties().UnicastAddresses
            .Select(unicast => unicast.Address)
            .FirstOrDefault(candidate =>
                candidate.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                !IPAddress.IsLoopback(candidate));
        return address?.ToString() ?? throw new InvalidOperationException("Không tìm thấy địa chỉ IPv4 của card mạng vật lý đang hoạt động.");
    }

    private string Build292ProxyBat(Proxy proxy, int localPort)
    {
        {
            var exportConfig = new AppConfig
            {
                SavedProxies = new List<Proxy> { proxy },
                ActiveProxyId = proxy.Id,
                LocalPort = localPort,
                UseVpnMode = true,
                ProxyMode = "all",
                AutoConnect = true
            };
            string configBase64 = Convert.ToBase64String(
                Encoding.UTF8.GetBytes(JsonSerializer.Serialize(exportConfig, ConfigJsonOptions)));
            string psScript = @"$ErrorActionPreference = 'Stop'
$root = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) '292VPN'
[IO.Directory]::CreateDirectory($root) | Out-Null
$bytes = [Convert]::FromBase64String('" + configBase64 + @"')
[IO.File]::WriteAllBytes((Join-Path $root 'config.json'), $bytes)
$candidates = @(
  (Join-Path $env:ProgramFiles '292VPN\292VPN.exe'),
  (Join-Path ${env:ProgramFiles(x86)} '292VPN\292VPN.exe'),
  (Join-Path $env:LOCALAPPDATA 'Programs\292VPN\292VPN.exe')
)
$app = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($app) { Start-Process -FilePath $app -WorkingDirectory (Split-Path -Parent $app) }
else { Write-Host '292VPN is not installed. Configuration was saved to LocalAppData.' }
";
            string commandBase64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(psScript));
            return "@echo off\r\npowershell.exe -NoProfile -EncodedCommand " + commandBase64 + "\r\n";
        }
    }

    // JSON mapping classes for Clash API response
    public class ClashConnectionsResponse
    {
        [JsonPropertyName("downloadTotal")]
        public long DownloadTotal { get; set; }

        [JsonPropertyName("uploadTotal")]
        public long UploadTotal { get; set; }

        [JsonPropertyName("connections")]
        public List<ClashConnection>? Connections { get; set; }
    }

    public class ClashConnection
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("metadata")]
        public ClashMetadata Metadata { get; set; } = new();

        [JsonPropertyName("upload")]
        public long Upload { get; set; }

        [JsonPropertyName("download")]
        public long Download { get; set; }

        [JsonPropertyName("start")]
        public string Start { get; set; } = string.Empty;

        [JsonPropertyName("chains")]
        public List<string>? Chains { get; set; }
    }

    public class ClashMetadata
    {
        [JsonPropertyName("network")]
        public string Network { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("sourceIP")]
        public string SourceIP { get; set; } = string.Empty;

        [JsonPropertyName("destinationIP")]
        public string DestinationIP { get; set; } = string.Empty;

        [JsonPropertyName("sourcePort")]
        public string SourcePort { get; set; } = string.Empty;

        [JsonPropertyName("destinationPort")]
        public string DestinationPort { get; set; } = string.Empty;

        [JsonPropertyName("host")]
        public string Host { get; set; } = string.Empty;

        [JsonPropertyName("processPath")]
        public string ProcessPath { get; set; } = string.Empty;
    }
}
