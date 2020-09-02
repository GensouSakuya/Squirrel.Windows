using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using NuGet;
using Splat;
using System.Reflection;
using System.IO.Compression;
using System.Management;
using System.ServiceProcess;

namespace Squirrel
{
    public sealed partial class UpdateManager
    {
        internal class InstallHelperImpl : IEnableLogger
        {
            readonly string applicationName;
            readonly string rootAppDirectory;
            private readonly bool isPerMachine;

            public InstallHelperImpl(string applicationName, string rootAppDirectory,bool isPerMachine = false)
            {
                this.applicationName = applicationName;
                this.rootAppDirectory = rootAppDirectory;
                this.isPerMachine = isPerMachine;
            }

            const string currentVersionRegSubKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
            const string uninstallRegSubKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
            public async Task<RegistryKey> CreateUninstallerRegistryEntry(string uninstallCmd, string quietSwitch)
            {
                var releaseContent = File.ReadAllText(Path.Combine(rootAppDirectory, "packages", "RELEASES"), Encoding.UTF8);
                var releases = ReleaseEntry.ParseReleaseFile(releaseContent);
                var latest = releases.Where(x => !x.IsDelta).OrderByDescending(x => x.Version).First();

                // Download the icon and PNG => ICO it. If this doesn't work, who cares
                var pkgPath = Path.Combine(rootAppDirectory, "packages", latest.Filename);
                var zp = new ZipPackage(pkgPath);
                    
                var targetPng = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".png");
                var targetIco = Path.Combine(rootAppDirectory, "app.ico");

                // NB: Sometimes the Uninstall key doesn't exist
                using (var parentKey =
                    RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default)
                        .CreateSubKey("Uninstall", RegistryKeyPermissionCheck.ReadWriteSubTree)) { ; }

                RegistryKey key;
                if (isPerMachine)
                {
                    key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
                            Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32)
                        .CreateSubKey(uninstallRegSubKey + "\\" + applicationName,
                            RegistryKeyPermissionCheck.ReadWriteSubTree);
                }
                else
                {
                    key = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default)
                        .CreateSubKey(uninstallRegSubKey + "\\" + applicationName, RegistryKeyPermissionCheck.ReadWriteSubTree);
                }
                if (zp.IconUrl != null && !File.Exists(targetIco)) {
                    try {
                        using (var wc = Utility.CreateWebClient()) { 
                            await wc.DownloadFileTaskAsync(zp.IconUrl, targetPng);
                            using (var fs = new FileStream(targetIco, FileMode.Create)) {
                                if (zp.IconUrl.AbsolutePath.EndsWith("ico")) {
                                    var bytes = File.ReadAllBytes(targetPng);
                                    fs.Write(bytes, 0, bytes.Length);
                                } else {
                                    using (var bmp = (Bitmap)Image.FromFile(targetPng))
                                    using (var ico = Icon.FromHandle(bmp.GetHicon())) {
                                        ico.Save(fs);
                                    }
                                }

                                key.SetValue("DisplayIcon", targetIco, RegistryValueKind.String);
                            }
                        }
                    } catch(Exception ex) {
                        this.Log().InfoException("Couldn't write uninstall icon, don't care", ex);
                    } finally {
                        File.Delete(targetPng);
                    }
                }
                else if (zp.IconUrl == null && !File.Exists(targetIco))
                {
                    try
                    {
                        using (var stream = File.OpenRead(pkgPath))
                        {
                            var p = new ZipArchive(stream);
                            var iconFile = p.GetEntry(@"app.ico");
                            if (iconFile != null)
                            {
                                iconFile.ExtractToFile(targetIco, true);
                            }
                        }
                        key.SetValue("DisplayIcon", targetIco, RegistryValueKind.String);
                    }
                    catch (Exception ex)
                    {
                        this.Log().InfoException("Couldn't write uninstall icon by extracting pkg, don't care", ex);
                    }
                }

                this.Log().Info($"Written to {key}");

                var stringsToWrite = new[] {
                    new { Key = "DisplayName", Value = zp.Title ?? zp.Description ?? zp.Summary },
                    new { Key = "DisplayVersion", Value = zp.Version.ToString() },
                    new { Key = "InstallDate", Value = DateTime.Now.ToString("yyyyMMdd") },
                    new { Key = "InstallLocation", Value = rootAppDirectory },
                    new { Key = "Publisher", Value = String.Join(",", zp.Authors) },
                    new { Key = "QuietUninstallString", Value = String.Format("{0} {1}", uninstallCmd, quietSwitch) },
                    new { Key = "UninstallString", Value = uninstallCmd },
                    new { Key = "URLUpdateInfo", Value = zp.ProjectUrl != null ? zp.ProjectUrl.ToString() : "", }
                };

                var dwordsToWrite = new[] {
                    new { Key = "EstimatedSize", Value = (int)((new FileInfo(pkgPath)).Length / 1024) },
                    new { Key = "NoModify", Value = 1 },
                    new { Key = "NoRepair", Value = 1 },
                    new { Key = "Language", Value = 0x0409 },
                };

                foreach (var kvp in stringsToWrite) {
                    key.SetValue(kvp.Key, kvp.Value, RegistryValueKind.String);
                }
                foreach (var kvp in dwordsToWrite) {
                    key.SetValue(kvp.Key, kvp.Value, RegistryValueKind.DWord);
                }

                return key;
            }

            public void KillAllProcessesBelongingToPackage()
            {
                var ourExe = Assembly.GetEntryAssembly();
                var ourExePath = ourExe != null ? ourExe.Location : null;

                UnsafeUtility.EnumerateProcesses()
                    .Where(x => {
                        // Processes we can't query will have an empty process name, we can't kill them
                        // anyways
                        if (String.IsNullOrWhiteSpace(x.Item1)) return false;

                        // Files that aren't in our root app directory are untouched
                        if (!x.Item1.StartsWith(rootAppDirectory, StringComparison.OrdinalIgnoreCase)) return false;

                        // Never kill our own EXE
                        if (ourExePath != null && x.Item1.Equals(ourExePath, StringComparison.OrdinalIgnoreCase)) return false;

                        var name = Path.GetFileName(x.Item1).ToLowerInvariant();
                        if (name == "squirrel.exe" || name == "update.exe") return false;

                        return true;
                    })
                    .ForEach(x => {
                        try {
                            this.WarnIfThrows(() =>
                            {
                                try
                                {
                                    if (IsService(x.Item2, out var serviceName))
                                        StopService(serviceName);
                                }
                                catch { }
                                Process.GetProcessById(x.Item2).Kill();
                            });
                        } catch {}
                    });
            }

            private static bool IsService(int pID, out string serviceName)
            {
                serviceName = null;
                using (ManagementObjectSearcher Searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_Service WHERE ProcessId =" + "\"" + pID + "\""))
                {
                    foreach (ManagementObject service in Searcher.Get())
                    {
                        serviceName = service["Name"]?.ToString();
                        return true;
                    }
                }
                return false;
            }

            private static void StopService(string serviceName)
            {
                if (string.IsNullOrWhiteSpace(serviceName))
                    return;
                ServiceController.GetServices().FirstOrDefault(p => p.ServiceName == serviceName)?.Stop();
            }

            public Task<RegistryKey> CreateUninstallerRegistryEntry()
            {
                var updateDotExe = Path.Combine(rootAppDirectory, "Update.exe");
                return CreateUninstallerRegistryEntry(
                    $"\"{updateDotExe}\" --uninstall {(isPerMachine ? "--per-machine" : string.Empty)}", "-s");
            }

            public void RemoveUninstallerRegistryEntry()
            {
                RegistryKey key;
                if (isPerMachine)
                {
                    key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
                            Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32)
                        .OpenSubKey(uninstallRegSubKey, true);
                }
                else
                {
                    key = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default)
                        .OpenSubKey(uninstallRegSubKey, true);
                }
                key.DeleteSubKeyTree(applicationName);
            }
        }
    }
}
