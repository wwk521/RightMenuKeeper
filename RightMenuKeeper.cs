using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace RightMenuKeeper {
    public class RegValue {
        public string Name { get; set; }
        public string Kind { get; set; }
        public string Text { get; set; }
        public string[] Strings { get; set; }
    }
    public class RegTree {
        public List<RegValue> Values { get; set; }
        public Dictionary<string, RegTree> Children { get; set; }
        public RegTree() { Values = new List<RegValue>(); Children = new Dictionary<string, RegTree>(); }
    }
    public class MenuEntry {
        public string Id { get; set; }
        public string Name { get; set; }
        public string FriendlyName {
            get {
                string s = (Name + " " + Product + " " + File + " " + Path + " " + Company).ToLowerInvariant();
                if (s.Contains("baidunetdisk") || s.Contains("baiduyunguanjia") || s.Contains("yunshell")) return "百度网盘";
                if (s.Contains("quarkshell") || s.Contains("quarkai.contextmenu")) return "夸克网盘";
                if (s.Contains("bandizip") || s.Contains("bdzshell") || s.Contains("aabdzctx") || s.Contains("bandisoft")) return "Bandizip 压缩软件";
                if (s.Contains("7-zip")) return "7-Zip 压缩软件";
                return Name;
            }
        }
        public string MenuHint {
            get {
                if (FriendlyName == "百度网盘") return "可能包含：上传到百度网盘、用手机打开、自动备份、同步至其它设备。此入口可能控制多个按钮。";
                if (FriendlyName == "夸克网盘") return "可能包含：上传到夸克网盘、自动备份文件夹。此入口可能控制多个按钮。";
                return Type == "Shell 扩展" ? "此入口可能控制多个右键按钮，取消勾选会一起禁用。" : "勾选表示保留，取消勾选表示禁用。";
            }
        }
        public string Scope { get; set; }
        public string Type { get; set; }
        public string Hive { get; set; }
        public string Path { get; set; }
        public string Command { get; set; }
        public string File { get; set; }
        public string Company { get; set; }
        public string Product { get; set; }
        public string Origin { get; set; }
        public string Fingerprint { get; set; }
        public string BackupId { get; set; }
        public string Note { get; set; }
        public bool Enabled { get; set; }
        public bool Desired { get; set; }
        public bool ReadOnly { get; set; }
        public bool Hidden { get; set; }
        public bool Missing { get; set; }
        public string Status {
            get {
                if (Desired != Enabled) return Desired ? "待恢复" : "待禁用";
                if (ReadOnly && Type == "打包应用菜单") return "仅检测";
                if (!Enabled) return "已禁用 · 可恢复";
                if (Hidden) return "系统已隐藏";
                if (Missing) return "文件不存在";
                return "已保留";
            }
        }
    }
    public class BackupRecord {
        public int Version { get; set; }
        public string Id { get; set; }
        public string CreatedUtc { get; set; }
        public string State { get; set; }
        public string UserSid { get; set; }
        public MenuEntry Entry { get; set; }
        public RegTree Tree { get; set; }
    }
    public class ScanResult {
        public List<MenuEntry> Entries { get; set; }
        public List<string> Warnings { get; set; }
        public ScanResult() { Entries = new List<MenuEntry>(); Warnings = new List<string>(); }
    }
    static class Engine {
        public static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024, RecursionLimit = 100 };
        public static string DataDirectory = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RightMenuKeeper", "Backups");
        public static string Sid { get { return WindowsIdentity.GetCurrent().User.Value; } }
        public static bool IsAdmin { get { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } }
        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)] static extern int SHLoadIndirectString(string source, StringBuilder output, uint size, IntPtr reserved);
        [DllImport("shell32.dll")] static extern void SHChangeNotify(uint eventId, uint flags, IntPtr a, IntPtr b);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegCreateKeyEx(SafeRegistryHandle key, string subKey, int reserved, string keyClass, int options, int access, IntPtr security, out SafeRegistryHandle result, out int disposition);
        public static RegistryKey Base(string hive) {
            if (hive != "HKCU" && hive != "HKLM") throw new InvalidDataException("注册表根位置无效。");
            return RegistryKey.OpenBaseKey(hive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine, RegistryView.Registry64);
        }
        public static void ValidateTarget(string hive, string path) {
            if (hive != "HKCU" && hive != "HKLM") throw new InvalidDataException("无效根位置。");
            if (path == null || !Regex.IsMatch(path, @"^Software\\Classes\\[^\\]+(?:\\[^\\]+)*\\(?:shell|shellex\\ContextMenuHandlers)\\[^\\]+$", RegexOptions.IgnoreCase))
                throw new InvalidDataException("只允许修改具体右键菜单注册项。");
            if (path.IndexOf("\0", StringComparison.Ordinal) >= 0) throw new InvalidDataException("无效路径。");
        }
        public static RegTree Capture(RegistryKey key) { int count = 0; return Capture(key, ref count, 0); }
        static RegTree Capture(RegistryKey key, ref int count, int depth) {
            if (++count > 2000 || depth > 40) throw new InvalidDataException("菜单注册树过大，已停止读取。");
            RegTree tree = new RegTree();
            foreach (string name in key.GetValueNames().OrderBy(x => x, StringComparer.Ordinal)) {
                RegistryValueKind kind = key.GetValueKind(name);
                object value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                RegValue item = new RegValue { Name = name, Kind = kind.ToString() };
                if (kind == RegistryValueKind.Binary || kind == RegistryValueKind.None) item.Text = Convert.ToBase64String((byte[])value);
                else if (kind == RegistryValueKind.MultiString) item.Strings = (string[])value;
                else if (kind == RegistryValueKind.DWord) item.Text = ((int)value).ToString(System.Globalization.CultureInfo.InvariantCulture);
                else if (kind == RegistryValueKind.QWord) item.Text = ((long)value).ToString(System.Globalization.CultureInfo.InvariantCulture);
                else if (kind == RegistryValueKind.String || kind == RegistryValueKind.ExpandString) item.Text = (string)value;
                else throw new InvalidDataException("不支持的注册表值类型：" + kind);
                tree.Values.Add(item);
            }
            foreach (string child in key.GetSubKeyNames().OrderBy(x => x, StringComparer.Ordinal)) {
                using (RegistryKey sub = key.OpenSubKey(child)) {
                    if (sub == null) throw new IOException("菜单注册项在读取时发生变化。");
                    tree.Children.Add(child, Capture(sub, ref count, depth + 1));
                }
            }
            return tree;
        }
        public static void Restore(RegistryKey key, RegTree tree) {
            foreach (RegValue value in tree.Values) {
                RegistryValueKind kind = (RegistryValueKind)Enum.Parse(typeof(RegistryValueKind), value.Kind);
                object data;
                if (kind == RegistryValueKind.Binary || kind == RegistryValueKind.None) data = Convert.FromBase64String(value.Text);
                else if (kind == RegistryValueKind.MultiString) data = value.Strings;
                else if (kind == RegistryValueKind.DWord) data = int.Parse(value.Text, System.Globalization.CultureInfo.InvariantCulture);
                else if (kind == RegistryValueKind.QWord) data = long.Parse(value.Text, System.Globalization.CultureInfo.InvariantCulture);
                else data = value.Text;
                key.SetValue(value.Name, data, kind);
            }
            foreach (var child in tree.Children) using (RegistryKey sub = key.CreateSubKey(child.Key)) Restore(sub, child.Value);
            key.Flush();
        }
        public static string Hash(RegTree tree) {
            using (SHA256 sha = SHA256.Create()) return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(Json.Serialize(tree))));
        }
        public static void WriteJson(string file, object value) {
            string directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(file));
            Directory.CreateDirectory(directory);
            string temp = file + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try {
                using (FileStream stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                    byte[] bytes = new UTF8Encoding(false).GetBytes(Json.Serialize(value));
                    stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
                }
                if (File.Exists(file)) File.Replace(temp, file, null); else File.Move(temp, file);
            } finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        static string BackupFile(string id) {
            Guid parsed;
            if (!Guid.TryParseExact(id, "N", out parsed)) throw new InvalidDataException("备份编号无效。");
            return System.IO.Path.Combine(DataDirectory, id + ".json");
        }
        static void ValidateTree(RegTree tree, int depth, ref int count) {
            if (tree == null || tree.Values == null || tree.Children == null || depth > 40 || ++count > 2000) throw new InvalidDataException("备份结构无效。");
            foreach (var child in tree.Children) {
                if (string.IsNullOrEmpty(child.Key) || child.Key.IndexOfAny(new [] {'\\', '\0'}) >= 0) throw new InvalidDataException("备份子项无效。");
                ValidateTree(child.Value, depth + 1, ref count);
            }
            foreach (RegValue value in tree.Values) {
                if (value == null || value.Name == null || value.Name.IndexOf('\0') >= 0) throw new InvalidDataException("备份值无效。");
                RegistryValueKind kind;
                if (!Enum.TryParse<RegistryValueKind>(value.Kind, out kind) || kind == RegistryValueKind.Unknown) throw new InvalidDataException("备份值类型无效。");
            }
        }
        static BackupRecord ReadBackup(string file) {
            if (new FileInfo(file).Length > 16 * 1024 * 1024) throw new InvalidDataException("备份过大。");
            BackupRecord record = Json.Deserialize<BackupRecord>(File.ReadAllText(file, Encoding.UTF8));
            if (record == null || record.Version != 1 || record.Entry == null || record.UserSid != Sid) throw new InvalidDataException("备份版本或用户不匹配。");
            ValidateTarget(record.Entry.Hive, record.Entry.Path);
            if (System.IO.Path.GetFileName(file) != record.Id + ".json") throw new InvalidDataException("备份文件名不匹配。");
            BackupFile(record.Id); int count = 0; ValidateTree(record.Tree, 0, ref count);
            if (Hash(record.Tree) != record.Entry.Fingerprint) throw new InvalidDataException("备份内容校验失败。");
            return record;
        }
        public static bool Exists(string hive, string path) {
            using (RegistryKey root = Base(hive)) using (RegistryKey key = root.OpenSubKey(path)) return key != null;
        }
        public static void Disable(MenuEntry entry) {
            ValidateTarget(entry.Hive, entry.Path);
            if (entry.ReadOnly) throw new InvalidOperationException("此项目只能检测。");
            using (RegistryKey root = Base(entry.Hive)) {
                RegTree tree;
                using (RegistryKey key = root.OpenSubKey(entry.Path)) {
                    if (key == null) throw new IOException("该项目已变化，请重新扫描。");
                    tree = Capture(key);
                }
                if (Hash(tree) != entry.Fingerprint) throw new IOException("该项目已被软件修改，请重新扫描后再决定。");
                BackupRecord record = new BackupRecord { Version = 1, Id = Guid.NewGuid().ToString("N"), CreatedUtc = DateTime.UtcNow.ToString("o"), State = "prepared", UserSid = Sid, Entry = entry, Tree = tree };
                string file = BackupFile(record.Id);
                WriteJson(file, record); // 删除前持久化并验证完整备份。
                ReadBackup(file);
                using (RegistryKey check = root.OpenSubKey(entry.Path)) {
                    if (check == null || Hash(Capture(check)) != entry.Fingerprint) throw new IOException("保存备份后项目发生变化，未执行删除。");
                }
                root.DeleteSubKeyTree(entry.Path, false); root.Flush();
                if (Exists(entry.Hive, entry.Path)) throw new IOException("软件重新创建了菜单，请重新扫描。");
                record.State = "disabled"; WriteJson(file, record);
            }
        }
        public static void Enable(MenuEntry entry) {
            ValidateTarget(entry.Hive, entry.Path);
            BackupRecord record = ReadBackup(BackupFile(entry.BackupId));
            if (record.Entry.Id != entry.Id || record.Entry.Path != entry.Path || record.Entry.Hive != entry.Hive) throw new InvalidDataException("备份与项目不匹配。");
            using (RegistryKey root = Base(entry.Hive)) {
                using (RegistryKey existing = root.OpenSubKey(entry.Path)) {
                    if (existing != null) throw new IOException("软件已重新创建这个菜单。为避免覆盖，请重新扫描。");
                }
                // 恢复中断时仍保留备份。
                record.State = "restoring"; WriteJson(BackupFile(record.Id), record);
                SafeRegistryHandle handle; int disposition;
                int error = RegCreateKeyEx(root.Handle, entry.Path, 0, null, 0, 0x2001f | 0x100, IntPtr.Zero, out handle, out disposition);
                if (error != 0) throw new System.ComponentModel.Win32Exception(error);
                using (handle) {
                    if (disposition != 1) throw new IOException("软件在恢复时重新创建了菜单，未覆盖其内容。请重新扫描。");
                    using (RegistryKey key = RegistryKey.FromHandle(handle, RegistryView.Registry64)) Restore(key, record.Tree);
                }
                using (RegistryKey check = root.OpenSubKey(entry.Path)) {
                    if (check == null || Hash(Capture(check)) != record.Entry.Fingerprint) throw new IOException("恢复校验失败。备份仍然保留，请检查后重试。");
                }
                record.State = "restored"; WriteJson(BackupFile(record.Id), record);
            }
        }
        public static void NotifyShell() { SHChangeNotify(0x08000000, 0, IntPtr.Zero, IntPtr.Zero); }
        static string Text(RegistryKey key, string name) { return Convert.ToString(key.GetValue(name, "", RegistryValueOptions.DoNotExpandEnvironmentNames)); }
        static string ResolveLabel(string label) {
            if (string.IsNullOrEmpty(label) || !label.StartsWith("@")) return label;
            StringBuilder output = new StringBuilder(1024);
            return SHLoadIndirectString(label, output, 1024, IntPtr.Zero) == 0 ? output.ToString() : label;
        }
        static string FindFile(string command) {
            string text = Environment.ExpandEnvironmentVariables(command ?? "").Trim();
            if (text.StartsWith("@")) text = text.Substring(1);
            Match match = Regex.Match(text, "^\"([^\"]+)\"|^(.+?\\.(?:exe|dll|cpl|ico))(?:[,\\s]|$)", RegexOptions.IgnoreCase);
            string file = match.Success ? (match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value) : "";
            if (file.Length > 0 && !System.IO.Path.IsPathRooted(file)) {
                string systemFile = System.IO.Path.Combine(Environment.SystemDirectory, file);
                if (File.Exists(systemFile)) return systemFile;
                if (file.IndexOfAny(new [] {'\\', '/'}) < 0) foreach (string directory in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';')) {
                    string localDirectory = Environment.ExpandEnvironmentVariables(directory.Trim().Trim('"'));
                    if (!Regex.IsMatch(localDirectory, @"^[A-Za-z]:\\")) continue;
                    try { string candidate = System.IO.Path.Combine(localDirectory, file); if (File.Exists(candidate)) return candidate; } catch { }
                }
            }
            return file;
        }
        static string ResolveClsid(string clsid, string valueName, bool server) {
            if (string.IsNullOrWhiteSpace(clsid)) return "";
            foreach (string hive in new [] {"HKCU", "HKLM"}) using (RegistryKey root = Base(hive)) {
                string prefix = @"Software\Classes\CLSID\" + clsid;
                if (server) foreach (string suffix in new [] {@"\InprocServer32", @"\LocalServer32"}) {
                    using (RegistryKey key = root.OpenSubKey(prefix + suffix)) if (key != null && Text(key, "").Length > 0) return Text(key, "");
                }
                else using (RegistryKey key = root.OpenSubKey(prefix)) if (key != null && Text(key, valueName).Length > 0) return Text(key, valueName);
            }
            return "";
        }
        static readonly Dictionary<string, string> Companies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<string, string> Products = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        static string Company(string file) {
            if (string.IsNullOrEmpty(file) || !File.Exists(file)) return "未识别";
            string company;
            if (Companies.TryGetValue(file, out company)) return company;
            try { FileVersionInfo info = FileVersionInfo.GetVersionInfo(file); company = info.CompanyName; Products[file] = info.ProductName ?? ""; } catch { company = ""; }
            if (string.IsNullOrWhiteSpace(company)) company = "未识别";
            Companies[file] = company; return company;
        }
        static void ReadMenuBranch(ScanResult result, string hive, string className, string scope, string branch, bool extension) {
            using (RegistryKey root = Base(hive)) {
                string parentPath = @"Software\Classes\" + className + "\\" + branch;
                using (RegistryKey parent = root.OpenSubKey(parentPath)) {
                    if (parent == null) return;
                    string defaultVerb = Text(parent, "");
                    foreach (string child in parent.GetSubKeyNames()) {
                        try {
                            using (RegistryKey key = parent.OpenSubKey(child)) {
                                if (key == null) continue;
                                string command = "", label = "", clsid = "";
                                if (extension) {
                                    clsid = Text(key, ""); if (clsid.Length == 0 && child.StartsWith("{")) clsid = child;
                                    label = ResolveLabel(ResolveClsid(clsid, "LocalizedString", false));
                                    if (label.Length == 0) label = ResolveClsid(clsid, "", false);
                                    command = ResolveClsid(clsid, "", true);
                                } else {
                                    label = ResolveLabel(Text(key, "MUIVerb"));
                                    if (label.Length == 0) label = ResolveLabel(Text(key, ""));
                                    using (RegistryKey cmd = key.OpenSubKey("command")) if (cmd != null) { command = Text(cmd, ""); clsid = Text(cmd, "DelegateExecute"); }
                                    if (clsid.Length == 0) clsid = Text(key, "ExplorerCommandHandler");
                                    if (command.Length == 0 && clsid.Length > 0) command = ResolveClsid(clsid, "", true);
                                }
                                if (string.IsNullOrEmpty(label)) label = child;
                                string path = parentPath + "\\" + child;
                                string file = FindFile(command); if (file.Length == 0) file = FindFile(Text(key, "Icon"));
                                bool protectedVerb = !extension && (new [] {"open", "opennewwindow", "explore", "find"}.Contains(child.ToLowerInvariant()) || (!string.IsNullOrEmpty(defaultVerb) && string.Equals(defaultVerb, child, StringComparison.OrdinalIgnoreCase)));
                                MenuEntry entry = new MenuEntry { Id = hive + "|64|" + path.ToLowerInvariant(), Name = label.Replace("&", ""), Scope = scope, Type = extension ? "Shell 扩展" : "普通菜单", Hive = hive, Path = path, Command = command, File = file, Company = Company(file), Enabled = true, Desired = true, ReadOnly = protectedVerb, Fingerprint = Hash(Capture(key)), Missing = file.Length > 0 && System.IO.Path.IsPathRooted(file) && !File.Exists(file), Hidden = key.GetValueNames().Any(n => n == "LegacyDisable" || n == "ProgrammaticAccessOnly") };
                                string product; if (file.Length > 0 && Products.TryGetValue(file, out product)) entry.Product = product;
                                if (protectedVerb) entry.Note = "这是打开文件/文件夹或默认操作，本版仅检测，以免影响双击打开。";
                                else if (extension) entry.Note = "一个 Shell 扩展可能生成多个按钮。禁用会移除它在此场景下生成的整组菜单。CLSID：" + clsid;
                                else if (Text(key, "SubCommands").Length > 0 || key.GetSubKeyNames().Contains("shell")) entry.Note = "这是级联菜单，禁用会同时移除此菜单及其子菜单。";
                                else entry.Note = "只修改这一个菜单注册项；应用前备份，重新勾选可以恢复。";
                                if (key.GetValueNames().Contains("Extended")) entry.Note += " 该项可能仅在按住 Shift 右键时显示。";
                                if (Text(key, "AppliesTo").Length > 0) entry.Note += " 显示条件：" + Text(key, "AppliesTo");
                                result.Entries.Add(entry);
                            }
                        } catch (Exception ex) { result.Warnings.Add(hive + "\\" + parentPath + "\\" + child + "：" + ex.Message); }
                    }
                }
            }
        }
        public static ScanResult Scan(bool packages) {
            Companies.Clear(); Products.Clear(); ScanResult result = new ScanResult();
            Dictionary<string, string> classes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                {"Directory\\Background", "文件夹空白处 / 桌面"}, {"DesktopBackground", "桌面"}, {"Directory", "文件夹"}, {"Folder", "文件夹"}, {"Drive", "磁盘"}, {"*", "所有文件"}, {"AllFilesystemObjects", "文件与文件夹"}, {"LibraryFolder", "库"}
            };
            foreach (string hive in new [] {"HKCU", "HKLM"}) {
                try {
                    using (RegistryKey root = Base(hive)) using (RegistryKey regClasses = root.OpenSubKey(@"Software\Classes")) {
                        if (regClasses != null) {
                            foreach (string extension in regClasses.GetSubKeyNames().Where(n => n.StartsWith("."))) using (RegistryKey key = regClasses.OpenSubKey(extension)) {
                                if (key == null) continue;
                                classes[extension] = "文件类型：" + extension;
                                string progid = Text(key, "");
                                if (progid.Length > 0 && progid.IndexOf('\\') < 0 && !classes.ContainsKey(progid)) classes[progid] = "文件类型：" + extension + " 等";
                            }
                            using (RegistryKey associations = regClasses.OpenSubKey("SystemFileAssociations")) if (associations != null) foreach (string type in associations.GetSubKeyNames()) classes["SystemFileAssociations\\" + type] = "文件类型：" + type;
                        }
                    }
                } catch (Exception ex) { result.Warnings.Add("读取文件类型来源：" + ex.Message); }
            }
            try {
                using (RegistryKey root = Base("HKCU")) using (RegistryKey fileExts = root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts")) {
                    if (fileExts != null) foreach (string ext in fileExts.GetSubKeyNames()) using (RegistryKey choice = fileExts.OpenSubKey(ext + @"\UserChoice")) {
                        if (choice == null) continue; string progid = Text(choice, "ProgId");
                        if (progid.Length > 0 && progid.IndexOf('\\') < 0 && !classes.ContainsKey(progid)) classes[progid] = "文件类型：" + ext + " 等";
                    }
                }
            } catch (Exception ex) { result.Warnings.Add("读取当前文件关联：" + ex.Message); }
            foreach (string hive in new [] {"HKCU", "HKLM"}) foreach (var target in classes) {
                try { ReadMenuBranch(result, hive, target.Key, target.Value, "shell", false); ReadMenuBranch(result, hive, target.Key, target.Value, @"shellex\ContextMenuHandlers", true); }
                catch (Exception ex) { result.Warnings.Add(hive + "\\" + target.Key + "：" + ex.Message); }
            }
            Dictionary<string, MenuEntry> active = result.Entries.ToDictionary(e => e.Id, StringComparer.OrdinalIgnoreCase);
            if (Directory.Exists(DataDirectory)) {
                Dictionary<string, BackupRecord> latest = new Dictionary<string, BackupRecord>(StringComparer.OrdinalIgnoreCase);
                foreach (string file in Directory.GetFiles(DataDirectory, "*.json")) {
                    try {
                        BackupRecord record = ReadBackup(file);
                        BackupRecord previous;
                        if (!latest.TryGetValue(record.Entry.Id, out previous) || string.CompareOrdinal(record.CreatedUtc, previous.CreatedUtc) > 0) latest[record.Entry.Id] = record;
                    } catch (Exception ex) { result.Warnings.Add("备份 " + System.IO.Path.GetFileName(file) + "：" + ex.Message); }
                }
                foreach (BackupRecord record in latest.Values) {
                    if (record.State == "restored") continue;
                    try {
                        MenuEntry entry = record.Entry;
                        if (!Exists(entry.Hive, entry.Path)) {
                            entry.Enabled = false; entry.Desired = false; entry.BackupId = record.Id; entry.Hidden = false;
                            entry.Note = "已由本工具禁用。重新勾选并应用即可恢复；备份：" + record.Id;
                            result.Entries.Add(entry);
                        } else {
                            MenuEntry existing;
                            if (active.TryGetValue(entry.Id, out existing)) existing.Note += " 软件已重新注册，或上次恢复需核对；不会自动再次禁用。历史备份：" + record.Id;
                            if (record.State == "restoring") result.Warnings.Add("有一项恢复未完成，请核对：" + entry.Name + "（保留备份 " + record.Id + "）");
                        }
                    } catch (Exception ex) { result.Warnings.Add("核对备份状态：" + ex.Message); }
                }
            }
            if (packages) AddPackages(result);
            foreach (MenuEntry entry in result.Entries) entry.Origin = ClassifyOrigin(entry);
            foreach (var group in result.Entries.Where(e => e.Type != "打包应用菜单").GroupBy(e => e.Path, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
                foreach (MenuEntry entry in group) entry.Note += " 此入口有多个注册来源；选择时会同步这些来源，避免删掉一项后 Windows 转用另一项。";
            result.Entries = result.Entries.OrderBy(ScopeRank).ThenBy(e => e.Scope).ThenBy(e => e.Name).ThenBy(e => e.Hive).ToList();
            return result;
        }
        static int ScopeRank(MenuEntry entry) {
            if (entry.Type == "打包应用菜单") return 20;
            if (entry.Scope == "文件夹空白处 / 桌面") return 0;
            if (entry.Scope == "桌面") return 1;
            if (entry.Scope == "文件夹") return 2;
            if (entry.Scope == "所有文件") return 3;
            if (entry.Scope == "文件与文件夹") return 4;
            if (entry.Scope == "磁盘") return 5;
            if (entry.Scope == "库") return 6;
            return 10;
        }
        public static string ClassifyOrigin(MenuEntry entry) {
            const string system = "Windows 默认项";
            const string thirdParty = "第三方软件";
            const string unknown = "来源待确认";
            if (entry.Type == "打包应用菜单") {
                string[] inbox = {"Microsoft.WindowsNotepad", "Microsoft.Windows.Photos", "Microsoft.Paint", "Microsoft.MSPaint", "Microsoft.WindowsCalculator", "Microsoft.WindowsTerminal", "Microsoft.WindowsSoundRecorder", "Microsoft.WindowsCamera", "Microsoft.WindowsAlarms", "Microsoft.ScreenSketch", "Microsoft.MicrosoftStickyNotes", "Microsoft.WindowsStore", "Microsoft.SecHealthUI"};
                return inbox.Contains(entry.Company ?? "", StringComparer.OrdinalIgnoreCase) ? system : thirdParty;
            }
            if (string.IsNullOrWhiteSpace(entry.File) || !System.IO.Path.IsPathRooted(entry.File)) return unknown;
            string windows = System.IO.Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.Windows)).TrimEnd('\\') + "\\";
            string file;
            try { file = System.IO.Path.GetFullPath(Environment.ExpandEnvironmentVariables(entry.File)); } catch { return unknown; }
            bool inWindows = file.StartsWith(windows, StringComparison.OrdinalIgnoreCase);
            bool microsoft = (entry.Company ?? "").IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!inWindows) return thirdParty;
            if (!microsoft) return entry.Company == "未识别" || string.IsNullOrWhiteSpace(entry.Company) ? unknown : thirdParty;
            string executable = System.IO.Path.GetFileName(file).ToLowerInvariant();
            string[] wrappers = {"rundll32.exe", "regsvr32.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "explorer.exe"};
            if (wrappers.Contains(executable)) {
                // 系统启动器也可能运行第三方程序，需检查实际目标。
                string expanded = Environment.ExpandEnvironmentVariables(entry.Command ?? "");
                foreach (Match match in Regex.Matches(expanded, "\"(?<file>[A-Za-z]:\\\\[^\"]+\\.(?:exe|dll|ps1|vbs|cmd|bat))\"|(?<file>[A-Za-z]:\\\\[^,\\s\"]+\\.(?:exe|dll|ps1|vbs|cmd|bat))", RegexOptions.IgnoreCase)) {
                    string payload = match.Groups["file"].Value;
                    if (string.Equals(payload, file, StringComparison.OrdinalIgnoreCase)) continue;
                    if (!payload.StartsWith(windows, StringComparison.OrdinalIgnoreCase)) return thirdParty;
                    string company = Company(payload);
                    if (company != "未识别" && company.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) < 0) return thirdParty;
                }
                string path = (entry.Path ?? "").ToLowerInvariant();
                bool knownDefault = entry.ReadOnly || path == @"software\classes\directory\background\shell\cmd" || path == @"software\classes\directory\background\shell\powershell" || path == @"software\classes\directory\shell\cmd" || path == @"software\classes\directory\shell\powershell";
                return knownDefault ? system : unknown;
            }
            return system;
        }
        static void AddPackages(ScanResult result) {
            string script = @"[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); $rows=@(); $issues=@(); Get-AppxPackage | ForEach-Object { $p=$_; try { $m=Get-AppxPackageManifest -Package $p.PackageFullName -ErrorAction Stop; foreach($e in $m.SelectNodes(""//*[local-name()='Extension' and @Category='windows.fileExplorerContextMenus']"")) { foreach($item in $e.SelectNodes("".//*[local-name()='ItemType']"")) { foreach($verb in $item.SelectNodes("".//*[local-name()='Verb']"")) { $rows += [pscustomobject]@{Name=$p.Name;Package=$p.PackageFullName;Scope=$item.GetAttribute('Type');Verb=$verb.GetAttribute('Id');Clsid=$verb.GetAttribute('Clsid');Location=$p.InstallLocation} } } } } catch { $issues += $p.Name + ': ' + $_.Exception.Message } }; [pscustomobject]@{Rows=$rows;Issues=$issues}|ConvertTo-Json -Depth 5 -Compress";
            try {
                ProcessStartInfo info = new ProcessStartInfo(System.IO.Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"), "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script))) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
                using (Process process = Process.Start(info)) {
                    Task<string> output = process.StandardOutput.ReadToEndAsync(); Task<string> error = process.StandardError.ReadToEndAsync();
                    if (!process.WaitForExit(20000)) { process.Kill(); result.Warnings.Add("打包应用检测超过 20 秒，未完成此部分。"); return; }
                    if (process.ExitCode != 0) { result.Warnings.Add("打包应用检测未完成：" + error.Result); return; }
                    var data = Json.Deserialize<Dictionary<string, object>>(output.Result);
                    var rows = (System.Collections.IEnumerable)data["Rows"];
                    foreach (object item in rows) {
                        var row = (Dictionary<string, object>)item;
                        string name = Convert.ToString(row["Name"]), package = Convert.ToString(row["Package"]), verb = Convert.ToString(row["Verb"]);
                        result.Entries.Add(new MenuEntry { Id = "package|" + package + "|" + verb + "|" + Convert.ToString(row["Scope"]), Name = name + " · " + verb, Scope = "Windows 11 新菜单：" + Convert.ToString(row["Scope"]), Type = "打包应用菜单", Hive = "应用包", Path = package, File = Convert.ToString(row["Location"]), Command = "CLSID：" + Convert.ToString(row["Clsid"]), Company = name, Enabled = true, Desired = true, ReadOnly = true, Note = "来自应用包清单。本版列出来源，仅检测；是否实际显示还取决于选择对象和应用条件。请在对应软件设置中关闭。" });
                    }
                    foreach (object issue in (System.Collections.IEnumerable)data["Issues"]) result.Warnings.Add("应用包：" + Convert.ToString(issue));
                }
            } catch (Exception ex) { result.Warnings.Add("打包应用检测：" + ex.Message); }
        }
        public static void SelfTest(string reportFile) {
            string path = @"Software\RightMenuKeeper\Tests\" + Guid.NewGuid().ToString("N");
            string fixtureClass = @"Software\Classes\RightMenuKeeper.Test." + Guid.NewGuid().ToString("N");
            string fixturePath = fixtureClass + @"\shell\TestVerb";
            string originalData = DataDirectory;
            string reportDir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(reportFile));
            string testData = System.IO.Path.GetFullPath(System.IO.Path.Combine(reportDir, "self-test-backups-" + Guid.NewGuid().ToString("N")));
            List<string> checks = new List<string>();
            using (RegistryKey root = Base("HKCU")) {
                try {
                    using (RegistryKey key = root.CreateSubKey(path)) {
                        key.SetValue("", "中文菜单"); key.SetValue("expand", "%USERPROFILE%\\测试", RegistryValueKind.ExpandString);
                        key.SetValue("binary", new byte[] {0, 1, 127, 255}, RegistryValueKind.Binary);
                        key.SetValue("multi", new [] {"第一项", "", "third"}, RegistryValueKind.MultiString);
                        key.SetValue("dword", -1, RegistryValueKind.DWord); key.SetValue("qword", long.MaxValue, RegistryValueKind.QWord);
                        using (RegistryKey sub = key.CreateSubKey("command")) sub.SetValue("", "\"C:\\测试\\tool.exe\" \"%V\"");
                    }
                    RegTree before; using (RegistryKey key = root.OpenSubKey(path)) before = Capture(key);
                    string hash = Hash(before); string roundTrip = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(reportFile), "test-snapshot.json"); WriteJson(roundTrip, before);
                    RegTree parsed = Json.Deserialize<RegTree>(File.ReadAllText(roundTrip, Encoding.UTF8));
                    if (hash != Hash(parsed)) throw new Exception("JSON roundtrip failed"); checks.Add("JSON：完整值类型与中文往返一致");
                    root.DeleteSubKeyTree(path);
                    using (RegistryKey key = root.CreateSubKey(path)) Restore(key, parsed);
                    using (RegistryKey key = root.OpenSubKey(path)) if (hash != Hash(Capture(key))) throw new Exception("Registry roundtrip failed");
                    checks.Add("隔离测试注册项：删除 / 恢复后完整指纹一致");
                    using (RegistryKey key = root.OpenSubKey(path, true)) key.SetValue("changed", "新内容");
                    using (RegistryKey key = root.OpenSubKey(path)) if (hash == Hash(Capture(key))) throw new Exception("Change detection failed"); checks.Add("内容变更可检测，避免覆盖新注册项");
                    foreach (string bad in new [] {@"Software\Classes", @"Software\Classes\Directory\shell", @"Software\Microsoft\Windows\CurrentVersion\Run\app"}) {
                        bool rejected = false; try { ValidateTarget("HKCU", bad); } catch (InvalidDataException) { rejected = true; }
                        if (!rejected) throw new Exception("Target guard failed");
                    }
                    ValidateTarget("HKCU", @"Software\Classes\Directory\Background\shell\Test");
                    ValidateTarget("HKLM", @"Software\Classes\*\shellex\ContextMenuHandlers\Test"); checks.Add("目标范围校验：只接受具体菜单注册项");
                    // 使用未关联的测试项，避免触碰用户菜单。
                    DataDirectory = testData;
                    using (RegistryKey fixture = root.CreateSubKey(fixturePath)) { fixture.SetValue("", "独立测试菜单"); using (RegistryKey cmd = fixture.CreateSubKey("command")) cmd.SetValue("", "test.exe \"%1\""); }
                    MenuEntry entry = new MenuEntry { Id = "HKCU|64|" + fixturePath.ToLowerInvariant(), Hive = "HKCU", Path = fixturePath, Name = "独立测试菜单", Scope = "测试", Type = "普通菜单", Enabled = true, Desired = false };
                    using (RegistryKey fixture = root.OpenSubKey(fixturePath)) entry.Fingerprint = Hash(Capture(fixture));
                    Disable(entry);
                    if (Exists("HKCU", fixturePath)) throw new Exception("Disable failed");
                    string saved = Directory.GetFiles(testData, "*.json").Single(); BackupRecord savedRecord = ReadBackup(saved);
                    if (savedRecord.State != "disabled") throw new Exception("Journal state failed"); entry.BackupId = savedRecord.Id;
                    checks.Add("真实禁用流程：先持久化完整备份，再删除独立测试注册项");
                    using (RegistryKey recreated = root.CreateSubKey(fixturePath)) recreated.SetValue("new", "软件新注册的内容");
                    bool conflict = false; try { Enable(entry); } catch (IOException) { conflict = true; }
                    using (RegistryKey recreated = root.OpenSubKey(fixturePath)) if (!conflict || Text(recreated, "new") != "软件新注册的内容") throw new Exception("Restore conflict guard failed");
                    checks.Add("恢复冲突保护：不会覆盖软件重新注册的项目");
                    root.DeleteSubKeyTree(fixturePath); Enable(entry);
                    using (RegistryKey fixture = root.OpenSubKey(fixturePath)) if (Hash(Capture(fixture)) != entry.Fingerprint) throw new Exception("Lifecycle roundtrip failed");
                    if (ReadBackup(saved).State != "restored") throw new Exception("Restore journal failed"); checks.Add("完整生命周期：禁用 / 恢复 / 备份状态一致");
                    using (RegistryKey fixture = root.OpenSubKey(fixturePath, true)) fixture.SetValue("changed", "变化");
                    bool changed = false; try { Disable(entry); } catch (IOException) { changed = true; }
                    if (!changed || !Exists("HKCU", fixturePath) || Directory.GetFiles(testData, "*.json").Length != 1) throw new Exception("Stale scan guard failed"); checks.Add("过期扫描保护：内容变化后拒绝删除，且不生成误导备份");
                    string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                    if (ClassifyOrigin(new MenuEntry { File = System.IO.Path.Combine(windowsDir, @"System32\shell32.dll"), Company = "Microsoft Corporation", Type = "Shell 扩展" }) != "Windows 默认项") throw new Exception("Windows classification failed");
                    foreach (MenuEntry application in new [] {
                        new MenuEntry { File = @"C:\Program Files\Microsoft Visual Studio\devenv.exe", Company = "Microsoft Corporation", Type = "普通菜单" },
                        new MenuEntry { File = @"C:\Program Files\Microsoft OneDrive\OneDrive.exe", Company = "Microsoft Corporation", Type = "Shell 扩展" },
                        new MenuEntry { File = System.IO.Path.Combine(windowsDir, @"System32\NvCpl.dll"), Company = "NVIDIA Corporation", Type = "Shell 扩展" },
                        new MenuEntry { File = System.IO.Path.Combine(windowsDir, @"System32\rundll32.exe"), Company = "Microsoft Corporation", Command = "rundll32.exe \"E:\\ThirdParty\\handler.dll\",Launch", Type = "普通菜单" }
                    }) if (ClassifyOrigin(application) != "第三方软件") throw new Exception("Third-party classification failed: " + application.File);
                    if (ClassifyOrigin(new MenuEntry { Type = "Shell 扩展", Company = "未识别" }) != "来源待确认") throw new Exception("Unknown classification failed");
                    checks.Add("来源分类：Windows 系统模块、微软独立应用、系统目录内 NVIDIA 模块、Windows 启动器调用第三方及未知项正确区分");
                    WriteJson(reportFile, new { passed = true, checks = checks, testedAt = DateTime.Now.ToString("o"), existingMenusModified = false });
                    File.Delete(roundTrip);
                } finally {
                    DataDirectory = originalData; root.DeleteSubKeyTree(path, false); root.DeleteSubKeyTree(fixtureClass, false);
                    if (Directory.Exists(testData) && testData.StartsWith(reportDir + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) Directory.Delete(testData, true);
                }
            }
        }
    }
    class MainForm : Form {
        ListView list = new ListView(); TextBox search = new TextBox(), detail = new TextBox(); ComboBox scope = new ComboBox(), kind = new ComboBox();
        CheckBox onlyThirdParty = new CheckBox(), advanced = new CheckBox();
        Label status = new Label(), countLabel = new Label(); Button apply = new Button(), scan = new Button(), admin = new Button();
        List<MenuEntry> entries = new List<MenuEntry>(); List<string> warnings = new List<string>(); bool rendering, busy;
        public MainForm(bool autoScan = true) {
            Text = "右键菜单管家"; Font = new Font("Microsoft YaHei UI", 9F); Size = new Size(1240, 830); MinimumSize = new Size(1020, 690); StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(245, 247, 250);
            TableLayoutPanel layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 7, Padding = new Padding(22, 18, 22, 18) };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48)); layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 128)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44)); Controls.Add(layout);
            Label title = new Label { Text = "右键菜单管家", Font = new Font("Microsoft YaHei UI", 22, FontStyle.Bold), AutoSize = true, ForeColor = Color.FromArgb(28, 42, 65), Dock = DockStyle.Fill }; layout.Controls.Add(title);
            Label subtitle = new Label { Text = "勾选保留，取消勾选禁用。只在点击「应用选择」后修改；每个项目先备份，可随时恢复。", Dock = DockStyle.Fill, ForeColor = Color.FromArgb(85, 99, 119), TextAlign = ContentAlignment.MiddleLeft }; layout.Controls.Add(subtitle);
            FlowLayoutPanel filters = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(0, 6, 0, 0) };
            filters.Controls.Add(new Label { Text = "搜索", AutoSize = true, Padding = new Padding(0, 5, 6, 0) }); search.Width = 180; filters.Controls.Add(search);
            scope.DropDownStyle = ComboBoxStyle.DropDownList; scope.Width = 190; scope.Items.Add("全部场景"); scope.Items.Add("常见右键场景"); scope.Items.Add("文件夹上右键"); scope.SelectedIndex = 1; filters.Controls.Add(scope);
            kind.DropDownStyle = ComboBoxStyle.DropDownList; kind.Width = 125; kind.Items.AddRange(new object[] {"全部状态", "已保留", "已禁用", "待修改", "文件不存在", "仅检测", "来源待确认"}); kind.SelectedIndex = 0; filters.Controls.Add(kind);
            onlyThirdParty.Text = "隐藏 Windows 默认项"; onlyThirdParty.AutoSize = true; onlyThirdParty.Padding = new Padding(7, 3, 0, 0); filters.Controls.Add(onlyThirdParty); advanced.Text = "高级详情"; advanced.AutoSize = true; advanced.Padding = new Padding(5, 3, 0, 0); filters.Controls.Add(advanced);
            countLabel.AutoSize = true; countLabel.Padding = new Padding(10, 5, 0, 0); filters.Controls.Add(countLabel); layout.Controls.Add(filters);
            list.View = View.Details; list.CheckBoxes = true; list.FullRowSelect = true; list.HideSelection = false; list.ShowItemToolTips = true; list.Dock = DockStyle.Fill; list.GridLines = false; list.BackColor = Color.White; list.BorderStyle = BorderStyle.FixedSingle;
            list.Columns.Add("保留 / 菜单名称", 255); list.Columns.Add("软件来源（推测）", 155); list.Columns.Add("出现位置", 195); list.Columns.Add("菜单类型", 105); list.Columns.Add("状态", 125); list.Columns.Add("来源", 85); list.Columns.Add("来源分类（推测）", 140); layout.Controls.Add(list);
            detail.Multiline = true; detail.ReadOnly = true; detail.ScrollBars = ScrollBars.Vertical; detail.Dock = DockStyle.Fill; detail.BackColor = Color.White; detail.BorderStyle = BorderStyle.FixedSingle; detail.Margin = new Padding(0, 12, 0, 0); detail.Text = "先选右键场景，再搜索软件名称（例如：百度网盘）。选择一项查看操作说明。\r\n灰色项目会说明原因：需要管理员授权，或只能查看。多个入口可能属于同一软件。\r\n列表检测注册来源；实际显示还取决于选择对象、Shift 键和软件条件。"; layout.Controls.Add(detail);
            FlowLayoutPanel buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(0, 10, 0, 0) };
            scan = Button("重新扫描", 100); apply = Button("应用选择", 115); apply.BackColor = Color.FromArgb(35, 99, 219); apply.ForeColor = Color.White;
            Button keep = Button("保留当前筛选", 125), disable = Button("禁用当前筛选", 125), backup = Button("打开备份", 100), errors = Button("扫描详情", 100), refresh = Button("重启资源管理器", 155);
            foreach (Button button in new [] {scan, apply, keep, disable, backup, errors, refresh}) buttons.Controls.Add(button); layout.Controls.Add(buttons);
            FlowLayoutPanel footer = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(0, 8, 0, 0) };
            admin = Button(Engine.IsAdmin ? "已以管理员运行" : "以管理员重新打开", 175); admin.Enabled = !Engine.IsAdmin; footer.Controls.Add(admin);
            status.AutoSize = true; status.MaximumSize = new Size(940, 0); status.Padding = new Padding(10, 4, 0, 0); footer.Controls.Add(status); layout.Controls.Add(footer);
            list.ItemCheck += CheckItem; list.SelectedIndexChanged += delegate { ShowDetail(); };
            search.TextChanged += delegate { Render(); }; scope.SelectedIndexChanged += delegate { Render(); }; kind.SelectedIndexChanged += delegate { Render(); };
            onlyThirdParty.CheckedChanged += delegate { Render(); }; advanced.CheckedChanged += delegate { ShowDetail(); };
            scan.Click += async delegate { if (ConfirmDiscard()) await Rescan(); };
            apply.Click += async delegate { await Apply(); };
            keep.Click += delegate { SelectVisible(true); }; disable.Click += delegate { SelectVisible(false); };
            backup.Click += delegate { Directory.CreateDirectory(Engine.DataDirectory); Process.Start(new ProcessStartInfo("explorer.exe", "\"" + Engine.DataDirectory + "\"") { UseShellExecute = true }); };
            errors.Click += delegate { MessageBox.Show(warnings.Count == 0 ? "扫描未报告读取错误。\n范围：64 位资源管理器、常见场景、文件类型菜单、Shell 扩展及应用包菜单。\n动态按钮、系统内置菜单及条件显示项不能仅靠注册表完整还原。" : string.Join("\r\n\r\n", warnings), "扫描详情", MessageBoxButtons.OK, MessageBoxIcon.Information); };
            refresh.Click += delegate { RestartExplorer(); }; admin.Click += delegate { Elevate(); };
            FormClosing += delegate(object sender, FormClosingEventArgs e) { if (!busy && !ConfirmDiscard()) e.Cancel = true; else if (busy) { e.Cancel = true; MessageBox.Show("正在扫描或应用，请等操作结束。", "操作进行中"); } };
            if (autoScan) Shown += async delegate { await Rescan(); };
        }
        static Button Button(string text, int width) { return new Button { Text = text, Width = width, Height = 30, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand, Margin = new Padding(0, 0, 10, 0), BackColor = Color.White }; }
        bool CanEdit(MenuEntry entry) { return !entry.ReadOnly && (Engine.IsAdmin || (entry.Hive != "HKLM" && !entries.Any(e => e.Hive == "HKLM" && string.Equals(e.Path, entry.Path, StringComparison.OrdinalIgnoreCase)))); }
        bool ConfirmDiscard() { return !entries.Any(e => e.Desired != e.Enabled) || MessageBox.Show("还有未应用的选择。丢弃这些选择吗？", "未应用的选择", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes; }
        void Busy(bool value, string message) { busy = value; scan.Enabled = !value; apply.Enabled = !value; list.Enabled = !value; status.Text = message; Cursor = value ? Cursors.WaitCursor : Cursors.Default; }
        async Task Rescan() {
            if (busy) return; Busy(true, "正在检测菜单来源和备份…");
            try {
                ScanResult result = await Task.Run(() => Engine.Scan(true)); entries = result.Entries; warnings = result.Warnings;
                rendering = true; string previous = Convert.ToString(scope.SelectedItem); scope.Items.Clear(); scope.Items.Add("全部场景"); scope.Items.Add("常见右键场景"); scope.Items.Add("文件夹上右键");
                foreach (string text in entries.Select(e => e.Scope).Distinct().OrderBy(x => x)) scope.Items.Add(text);
                scope.SelectedIndex = Math.Max(0, scope.Items.IndexOf(previous)); rendering = false; Render();
                status.Text = "扫描完成 · " + entries.Count + " 个注册来源 · " + warnings.Count + " 条检测提示";
            } catch (Exception ex) { status.Text = "扫描失败"; MessageBox.Show(ex.Message, "扫描失败", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            finally { busy = false; scan.Enabled = true; apply.Enabled = true; list.Enabled = true; Cursor = Cursors.Default; }
        }
        bool VisibleEntry(MenuEntry entry) {
            if (onlyThirdParty.Checked && entry.Origin == "Windows 默认项") return false;
            string text = search.Text.Trim(); if (text.Length > 0 && (entry.FriendlyName + " " + entry.MenuHint + " " + entry.Name + " " + entry.Company + " " + entry.Product + " " + entry.Path + " " + entry.Command).IndexOf(text, StringComparison.OrdinalIgnoreCase) < 0) return false;
            string selectedScope = Convert.ToString(scope.SelectedItem);
            if (selectedScope == "常见右键场景" && entry.Scope.StartsWith("文件类型：")) return false;
            if (selectedScope == "文件夹上右键") { if (entry.Scope != "文件夹" && entry.Scope != "文件与文件夹" && entry.Scope != "Windows 11 新菜单：Directory") return false; }
            else if (scope.SelectedIndex > 2 && entry.Scope != selectedScope) return false;
            string selected = Convert.ToString(kind.SelectedItem);
            if (selected == "已保留" && !entry.Enabled) return false; if (selected == "已禁用" && entry.Enabled) return false;
            if (selected == "待修改" && entry.Desired == entry.Enabled) return false; if (selected == "文件不存在" && !entry.Missing) return false;
            if (selected == "仅检测" && CanEdit(entry)) return false;
            if (selected == "来源待确认" && entry.Origin != "来源待确认") return false;
            return true;
        }
        public void Render() {
            if (rendering) return; rendering = true; list.BeginUpdate(); list.Items.Clear();
            foreach (MenuEntry entry in entries.Where(VisibleEntry)) {
                ListViewItem row = new ListViewItem(entry.FriendlyName) { Tag = entry, Checked = entry.Desired, ToolTipText = entry.Note, ForeColor = CanEdit(entry) ? Color.FromArgb(32, 44, 60) : Color.FromArgb(115, 122, 135) };
            row.SubItems.Add(entry.FriendlyName != entry.Name ? entry.FriendlyName : (string.IsNullOrWhiteSpace(entry.Product) ? entry.Company : entry.Product)); row.SubItems.Add(entry.Scope); row.SubItems.Add(entry.Type == "Shell 扩展" ? "一组菜单按钮" : entry.Type == "打包应用菜单" ? "Windows 11 菜单" : entry.Type); row.SubItems.Add(!CanEdit(entry) && !entry.ReadOnly ? "需管理员授权" : entry.Status); row.SubItems.Add(entry.Hive == "HKCU" ? "当前用户" : entry.Hive == "HKLM" ? "所有用户" : "应用包"); row.SubItems.Add(entry.Origin ?? "来源待确认"); list.Items.Add(row);
                if (entry.Desired != entry.Enabled) row.BackColor = Color.FromArgb(237, 244, 255);
            }
            list.EndUpdate(); rendering = false; UpdateCount();
        }
        void UpdateCount() { countLabel.Text = "显示 " + list.Items.Count + " / " + entries.Count + " · 待修改 " + entries.Count(e => e.Desired != e.Enabled); }
        void CheckItem(object sender, ItemCheckEventArgs e) {
            if (rendering) return; MenuEntry entry = (MenuEntry)list.Items[e.Index].Tag;
            if (!CanEdit(entry)) { e.NewValue = e.CurrentValue; status.Text = !Engine.IsAdmin && !entry.ReadOnly ? "这项或它的另一份来源属于所有用户，请先点击「以管理员重新打开」。" : "此项仅检测。选择它可以查看原因和来源。"; return; }
            bool retained = e.NewValue == CheckState.Checked;
            foreach (MenuEntry linked in entries.Where(x => x.Type != "打包应用菜单" && string.Equals(x.Path, entry.Path, StringComparison.OrdinalIgnoreCase))) if (CanEdit(linked)) linked.Desired = retained;
            rendering = true;
            foreach (ListViewItem row in list.Items) {
                MenuEntry linked = (MenuEntry)row.Tag;
                if (string.Equals(linked.Path, entry.Path, StringComparison.OrdinalIgnoreCase)) {
                    if (row.Index != e.Index) row.Checked = linked.Desired;
                    row.SubItems[4].Text = linked.Status; row.BackColor = linked.Desired != linked.Enabled ? Color.FromArgb(237, 244, 255) : Color.White;
                }
            }
            rendering = false; UpdateCount();
        }
        void SelectVisible(bool retained) {
            if (busy) return;
            foreach (ListViewItem row in list.Items) { MenuEntry entry = (MenuEntry)row.Tag; if (CanEdit(entry)) foreach (MenuEntry linked in entries.Where(x => x.Type != "打包应用菜单" && string.Equals(x.Path, entry.Path, StringComparison.OrdinalIgnoreCase))) if (CanEdit(linked)) linked.Desired = retained; } Render();
        }
        void ShowDetail() {
            if (list.SelectedItems.Count == 0) return; MenuEntry entry = (MenuEntry)list.SelectedItems[0].Tag;
            if (!advanced.Checked) { detail.Text = entry.FriendlyName + " · " + entry.Scope + "\r\n" + entry.MenuHint + "\r\n" + (entry.ReadOnly ? "这一项仅供查看，本版不能修改。Windows 11 新菜单可能仍然显示。" : !CanEdit(entry) ? "请点击下方「以管理员重新打开」，授权后即可修改这一项。" : "取消勾选后点击「应用选择」；需要恢复时重新勾选并应用。") + "\r\n来源分类：" + entry.Origin + "（推测）。"; return; }
            detail.Text = entry.Name + " · " + entry.Origin + "（推测）\r\n" + entry.Note + "\r\n来源：" + entry.Hive + "\\" + entry.Path + "\r\n命令 / 模块：" + (entry.Command ?? "") + "\r\n软件来源：" + entry.Product + " / " + entry.Company + "（系统路径、版本信息和应用包名称判断，非数字签名验证）" + (!CanEdit(entry) && entry.Hive == "HKLM" && !entry.ReadOnly ? "；编辑需要管理员权限" : "");
        }
        async Task Apply() {
            if (busy) return; List<MenuEntry> changes = entries.Where(e => e.Desired != e.Enabled).ToList();
            if (changes.Count == 0) { status.Text = "没有待修改项目。取消勾选你不需要的菜单后再应用。"; return; }
            string summary = string.Join("\r\n", changes.Take(24).Select(e => (e.Desired ? "恢复：" : "禁用：") + e.FriendlyName + "  [" + e.Scope + "]"));
            if (changes.Count > 24) summary += "\r\n…另有 " + (changes.Count - 24) + " 项";
            if (MessageBox.Show(summary + "\r\n\r\n共 " + changes.Count + " 项。每项会先保存备份。应用这些选择？", "确认应用选择", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            Busy(true, "正在逐项保存备份并应用…"); int done = 0; List<string> failed = new List<string>();
            try {
                await Task.Run(() => { foreach (MenuEntry entry in changes) { try { if (!CanEdit(entry)) throw new InvalidOperationException("没有修改权限。"); if (entry.Desired) Engine.Enable(entry); else Engine.Disable(entry); done++; } catch (Exception ex) { failed.Add(entry.Name + "：" + ex.Message); } } Engine.NotifyShell(); });
            } finally { busy = false; scan.Enabled = true; apply.Enabled = true; list.Enabled = true; Cursor = Cursors.Default; }
            await Rescan(); status.Text = "已应用 " + done + " 项；失败 " + failed.Count + " 项。若菜单仍显示，可手动重启资源管理器。";
            if (failed.Count > 0) MessageBox.Show(string.Join("\r\n\r\n", failed), "部分项目未修改", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        void RestartExplorer() {
            if (busy) return;
            if (MessageBox.Show("桌面和任务栏会短暂消失，打开的文件夹窗口会关闭。\r\n请先结束文件复制或移动。现在重启资源管理器？", "刷新右键菜单", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            try {
                int session = Process.GetCurrentProcess().SessionId;
                foreach (Process process in Process.GetProcessesByName("explorer")) { using (process) if (process.SessionId == session) { process.Kill(); process.WaitForExit(5000); } }
                Process.Start(new ProcessStartInfo(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe")) { UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden }); status.Text = "已刷新资源管理器。请重新打开右键菜单。";
            } catch (Exception ex) { MessageBox.Show(ex.Message, "刷新失败", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }
        void Elevate() {
            if (busy || !ConfirmDiscard()) return;
            try {
                Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--user " + Engine.Sid + " --data \"" + Engine.DataDirectory + "\"") { UseShellExecute = true, Verb = "runas" });
                foreach (MenuEntry entry in entries) entry.Desired = entry.Enabled; Close();
            } catch (System.ComponentModel.Win32Exception ex) { status.Text = ex.NativeErrorCode == 1223 ? "已取消管理员授权，未修改任何项目。" : "管理员启动失败：" + ex.Message; }
        }
        public async Task CapturePreview(string file) {
            await Rescan(); Show(); Render(); Application.DoEvents();
            using (Bitmap image = new Bitmap(Width, Height)) { DrawToBitmap(image, new Rectangle(0, 0, Width, Height)); image.Save(file, System.Drawing.Imaging.ImageFormat.Png); }
        }
        public List<string> TestInteractions() {
            IntPtr listHandle = list.Handle; // 创建原生控件以验证真实勾选事件。
            List<string> checks = new List<string>();
            MenuEntry a = new MenuEntry { Id = "test-a", Name = "软件甲", Company = "测试", Origin = "第三方软件", Hive = "HKCU", Path = @"Software\Classes\TestOnly\shell\A", Scope = "桌面", Type = "普通菜单", Enabled = true, Desired = true };
            MenuEntry b = new MenuEntry { Id = "test-b", Name = "软件乙", Company = "测试", Origin = "Windows 默认项", Hive = "HKCU", Path = @"Software\Classes\TestOnly\shell\B", Scope = "文件夹", Type = "普通菜单", Enabled = true, Desired = true };
            entries = new List<MenuEntry> {a, b}; scope.SelectedIndex = 0; Render(); list.Items[0].Checked = false;
            if (a.Desired || a.Status != "待禁用") throw new Exception("Checkbox change failed: desired=" + a.Desired + ", checked=" + list.Items[0].Checked + ", status=" + a.Status);
            search.Text = "软件乙"; if (list.Items.Count != 1 || a.Desired) throw new Exception("Filter retention failed");
            search.Text = ""; if (list.Items[0].Checked) throw new Exception("Filter restore failed"); checks.Add("界面：勾选状态与待修改状态一致，筛选切换不会丢失选择");
            onlyThirdParty.Checked = true;
            if (list.Items.Count != 1 || list.Items[0].Tag != a || a.Desired || !b.Desired) throw new Exception("Third-party toggle failed");
            onlyThirdParty.Checked = false;
            if (list.Items.Count != 2 || a.Desired || !b.Desired) throw new Exception("Third-party toggle selection retention failed");
            checks.Add("界面：只显示第三方开关仅筛选列表，不改变保留选择");
            MenuEntry linked = new MenuEntry { Id = "test-linked", Name = "同一入口另一来源", Company = "测试", Hive = "HKCU", Path = a.Path, Scope = a.Scope, Type = a.Type, Enabled = true, Desired = true };
            a.Desired = true; entries.Add(linked); Render(); list.Items[0].Checked = false;
            if (a.Desired || linked.Desired) throw new Exception("Linked sources failed"); checks.Add("界面：同一路径的多个来源会联动选择");
            MenuEntry readOnly = new MenuEntry { Id = "test-readonly", Name = "仅检测项", Hive = "应用包", Path = "test-package", Scope = "测试", Type = "打包应用菜单", Enabled = true, Desired = true, ReadOnly = true };
            entries.Add(readOnly); Render(); ListViewItem locked = list.Items.Cast<ListViewItem>().First(x => x.Tag == readOnly); locked.Checked = false;
            if (!readOnly.Desired || !locked.Checked) throw new Exception("Readonly checkbox failed"); checks.Add("界面：仅检测项目不能被误加入禁用计划");
            MenuEntry baidu = new MenuEntry { Name = "YunShellExtContextMenu Class", Product = "BaiduYunGuanjia Application", Scope = "文件夹", Type = "Shell 扩展", Hive = "HKCU", Path = "test-baidu", Enabled = true, Desired = true };
            MenuEntry modern = new MenuEntry { Name = "BaiduNetdisk.DesktopSyncClient", Scope = "Windows 11 新菜单：Directory", Type = "打包应用菜单", ReadOnly = true, Enabled = true, Desired = true };
            entries = new List<MenuEntry> { baidu, modern }; search.Text = "百度网盘"; scope.SelectedIndex = scope.Items.IndexOf("文件夹上右键"); Render();
            if (list.Items.Count != 2 || baidu.FriendlyName != "百度网盘") throw new Exception("Chinese software discovery or folder scene failed");
            onlyThirdParty.Checked = true;
            if (list.Items.Count != 2) throw new Exception("Unknown sources must remain discoverable");
            checks.Add("界面：百度网盘中文搜索同时找到文件夹经典菜单和 Windows 11 菜单，未知来源不会被隐藏");
            foreach (MenuEntry item in entries) item.Desired = item.Enabled;
            return checks;
        }
    }
    static class Program {
        [STAThread] static int Main(string[] args) {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            try {
                for (int i = 0; i < args.Length; i++) {
                    if (args[i] == "--data" && i + 1 < args.Length) Engine.DataDirectory = System.IO.Path.GetFullPath(args[++i]);
                    else if (args[i] == "--user" && i + 1 < args.Length && args[++i] != Engine.Sid) throw new InvalidOperationException("请使用同一个 Windows 用户提升权限，以免修改其他用户的菜单。");
                }
                if (args.Contains("--self-test")) {
                    string file = System.IO.Path.GetFullPath(args[Array.IndexOf(args, "--self-test") + 1]); Engine.SelfTest(file);
                    using (MainForm form = new MainForm(false)) {
                        form.CreateControl(); var report = Engine.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(file, Encoding.UTF8)); report["interfaceChecks"] = form.TestInteractions(); Engine.WriteJson(file, report);
                    }
                    return 0;
                }
                if (args.Contains("--scan")) { string file = args[Array.IndexOf(args, "--scan") + 1]; Engine.WriteJson(System.IO.Path.GetFullPath(file), Engine.Scan(true)); return 0; }
                if (args.Contains("--ui-test")) {
                    string file = System.IO.Path.GetFullPath(args[Array.IndexOf(args, "--ui-test") + 1]);
                    using (MainForm form = new MainForm(false)) {
                        form.Shown += async delegate { try { await form.CapturePreview(file); } catch (Exception ex) { File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "last-error.txt"), ex.ToString()); Environment.ExitCode = 1; } finally { form.Close(); } };
                        Application.Run(form);
                    }
                    return Environment.ExitCode;
                }
                Application.Run(new MainForm()); return 0;
            } catch (Exception ex) { if (args.Length > 0) File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "last-error.txt"), ex.ToString(), Encoding.UTF8); else MessageBox.Show(ex.Message, "右键菜单管家", MessageBoxButtons.OK, MessageBoxIcon.Error); return 1; }
        }
    }
}
