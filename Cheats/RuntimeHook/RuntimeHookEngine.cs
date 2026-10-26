using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace FH6Mod.Cheats.RuntimeHook;

/// <summary>
/// Direct port of the Autoshow Unlocker v1.3.0 runtime hook engine.
/// Owns the FH6 process handle, the CRC bypass arming, and installs/removes
/// per-feature function detours. All offsets and ASM bytes match v1.3.0.
/// </summary>
public sealed class RuntimeHookEngine : IDisposable
{
    private readonly object _lock = new();
    private readonly Dictionary<string, RuntimeDetour> _hooks = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<ulong> _hookedAddresses = new();

    // Weather capture hook: newer builds contain multiple copies of tiny getter
    // functions; we hook ALL matches and use whichever captures a valid entity
    // at runtime. (The season feature no longer uses a capture hook — it talks to
    // the game's SeasonManager singleton directly, see SeasonChanger.)
    private readonly List<ulong> _weatherEntityStorageAddrs = new();
    private bool _weatherHookInstalled;

    // XP capture hook: AddTotalXP(owner, amount) entry hook
    private ulong _xpOwnerStorageAddr;
    private ulong _xpAddFunctionAddr;
    private bool _xpHookInstalled;
    private readonly Dictionary<string, ulong> _preResolvedTargets = new(StringComparer.OrdinalIgnoreCase);
    private bool _preResolved;

    private IntPtr _handle;
    private Process? _process;
    private ulong _mainBase;
    private int _mainSize;
    private bool _crcBypassActive;
    private ulong _crcFunctionPointerAddress;
    private ulong _crcOriginalPointer;
    private ulong _crcRetAddress;
    private Timer? _crcTimer;
    private int _crcTimerRunning;

    private Action<string>? _onLog;
    public bool IsAttached => _handle != IntPtr.Zero && _process is { HasExited: false };
    public int? Pid => _process is { HasExited: false } p ? p.Id : null;
    public List<string> Log { get; } = new();
    public void SetLogCallback(Action<string> onLog) => _onLog = onLog;

    /// <summary>
    /// Test all known signatures against the current FH6 binary without installing hooks.
    /// Returns (feature, found: bool, detail: string) for each.
    /// </summary>
    public List<(RuntimeProfileFeature Feature, bool Found, string Detail)> ScanAllSignatures()
    {
        var results = new List<(RuntimeProfileFeature, bool, string)>();
        if (!IsAttached || _mainBase == 0 || _mainSize <= 0)
        {
            foreach (RuntimeProfileFeature f in Enum.GetValues<RuntimeProfileFeature>())
                results.Add((f, false, "Not attached"));
            return results;
        }

        var moduleBytes = ReadBytes(_mainBase, _mainSize);
        if (moduleBytes.Length == 0)
        {
            foreach (RuntimeProfileFeature f in Enum.GetValues<RuntimeProfileFeature>())
                results.Add((f, false, "Could not read module"));
            return results;
        }

        foreach (RuntimeProfileFeature f in Enum.GetValues<RuntimeProfileFeature>())
        {
            try
            {
                var desc = ProfileFeatureCatalog.Get(f);
                var brokenPrefix = desc.BrokenNote is not null ? $"[BROKEN: {desc.BrokenNote}] " : "";
                bool found = false;
                string detail = $"{brokenPrefix}Signature not found";

                var sigs = new List<(string Sig, string Label)> { (desc.Signature, "primary") };
                foreach (var alt in desc.AltSignatures)
                    sigs.Add((alt, "alt"));

                foreach (var (sig, label) in sigs)
                {
                    if (found) break;
                    var pattern = Pattern.Parse(sig);

                    foreach (var off in Pattern.FindAll(moduleBytes, pattern, 128))
                    {
                        ulong hookAddr;
                        if (desc.ResolveCallTarget)
                        {
                            var callAddr = _mainBase + (ulong)off;
                            var head = ReadBytes(callAddr, 5);
                            if (head.Length < 5 || head[0] != 0xE8) continue;
                            var rel = BitConverter.ToInt32(head, 1);
                            hookAddr = (ulong)((long)(callAddr + 5) + rel + desc.CallTargetOffset);
                        }
                        else
                        {
                            hookAddr = (ulong)((long)_mainBase + off + desc.MatchOffset);
                        }

                        var original = ReadBytes(hookAddr, desc.HookSize);
                        if (original.Length < desc.HookSize) continue;

                        if (original.Length > 0 && original[0] == 0xE9)
                        {
                            detail = "Already patched by another tool";
                            continue;
                        }


                        // Validate struct offset range for MOV/ADD [rbx+disp32] patterns
                        if (original.Length >= 6 && (original[0] == 0x89 || original[0] == 0x01) && original[1] == 0x83)
                        {
                            var so = BitConverter.ToInt32(original, 2);
                            if (so < 0 || so > 0x2000)
                                continue;
                        }

                        if (BytesStartWith(original, desc.ExpectedOriginal))
                        {
                            found = true;
                            detail = $"{brokenPrefix}Match @ 0x{hookAddr:X} ({label}, exact{ExtractStructOffset(original, desc)})";
                            break;
                        }

                        detail = $"{brokenPrefix}Bytes mismatch @ 0x{hookAddr:X} ({label}): expected {FormatBytes(desc.ExpectedOriginal)}, got {FormatBytes(original)}";
                    }
                }

                results.Add((f, found, detail));
            }
            catch (Exception ex)
            {
                results.Add((f, false, ex.Message));
            }
        }
        return results;
    }

    // ===== Public surface for sibling subsystems (e.g. SqlExecutor) =====
    public IntPtr HandlePublic => _handle;
    public ulong  MainBase     => _mainBase;
    public int    MainSize     => _mainSize;
    public byte[] ReadBytesPublic(ulong addr, int len) => ReadBytes(addr, len);
    public ulong  ReadUInt64Public(ulong addr)         => ReadUInt64(addr);
    public int    ReadInt32Public(ulong addr)           => ReadInt32(addr);
    public void   WriteBytesPublic(ulong addr, byte[] data) => WriteBytes(addr, data);
    public void   WriteInt32Public(ulong addr, int value) => WriteInt32(addr, value);
    public bool   IsExecutableAddressPublic(ulong addr) => IsExecutableAddress(addr);

    /// <summary>
    /// Writes the game's main module exactly as it sits in memory to <paramref name="path"/>
    /// (plus a sidecar .txt with base/size/pid). The shipped exe is partially encrypted on
    /// disk and decrypted at load, so this is the only image worth analysing when a new
    /// game build breaks a signature. Read-only with respect to the game.
    /// </summary>
    public void DumpMainModule(string path)
    {
        if (!IsAttached || _mainBase == 0 || _mainSize <= 0)
            throw new InvalidOperationException("Not attached.");
        const int chunk = 1 << 20;
        using var fs = new System.IO.FileStream(path, System.IO.FileMode.Create, System.IO.FileAccess.Write);
        var zeroPage = new byte[4096];
        for (var off = 0; off < _mainSize; off += chunk)
        {
            var n = Math.Min(chunk, _mainSize - off);
            var b = ReadBytes(_mainBase + (ulong)off, n);
            if (b.Length == n) { fs.Write(b, 0, n); continue; }
            // A single unreadable page must not blank a whole chunk — fall back to pages.
            for (var p = 0; p < n; p += 4096)
            {
                var pn = Math.Min(4096, n - p);
                var pb = ReadBytes(_mainBase + (ulong)(off + p), pn);
                fs.Write(pb.Length == pn ? pb : zeroPage, 0, pn);
            }
        }
        System.IO.File.WriteAllText(path + ".txt", $"base=0x{_mainBase:X} size={_mainSize} pid={Pid}\n");
        L($"Module dumped to {path} ({_mainSize} bytes)");
    }

    /// <summary>
    /// Returns the first captured weather entity pointer from any of the hooked
    /// getter copies that has been called by the game.
    /// </summary>
    public ulong? GetCapturedWeatherEntity()
    {
        foreach (var storage in _weatherEntityStorageAddrs)
        {
            var ptr = ReadUInt64(storage);
            if (ptr != 0) return ptr;
        }
        return null;
    }

    /// <summary>Whole main module as it sits in memory (decrypted). ~180 MB, so cache per use.</summary>
    public byte[] ReadModuleBytesPublic() => IsAttached ? ReadBytes(_mainBase, _mainSize) : [];

    public bool IsInModule(ulong addr) => _mainBase != 0 && addr >= _mainBase && addr < _mainBase + (ulong)_mainSize;

    public bool HasDetour(string name) { lock (_lock) return _hooks.ContainsKey(name); }

    /// <summary>
    /// Installs a JMP detour at <paramref name="hookAddr"/> to a cave whose code the caller
    /// builds (the builder receives the cave address; it must re-emit the overwritten
    /// original instructions and the jump back itself). The detour is registered like any
    /// other hook, so the CRC bypass timer keeps it alive and Detach restores the site.
    /// Returns the cave address.
    /// </summary>
    public ulong InstallCustomDetour(string name, ulong hookAddr, int hookSize, int caveSize, Func<ulong, byte[]> buildCave)
    {
        if (hookSize < 5) throw new ArgumentException("hookSize must be >= 5");
        lock (_lock)
        {
            if (_hooks.TryGetValue(name, out var existing)) return existing.DetourAddress;
            if (!IsAttached) throw new InvalidOperationException("Not attached.");
            EnsureCrcBypass();

            var original = ReadBytes(hookAddr, hookSize);
            if (original.Length != hookSize)
                throw new InvalidOperationException($"{name}: could not read hook site 0x{hookAddr:X}.");
            if (original[0] == 0xE9)
                throw new InvalidOperationException($"{name}: hook site 0x{hookAddr:X} is already patched by another tool. Close other trainers and retry.");

            var caveAddr = AllocateNear(hookAddr, caveSize);
            var cave = buildCave(caveAddr);
            if (cave.Length > Math.Max(caveSize, 4096))
                throw new InvalidOperationException($"{name}: cave code ({cave.Length} B) exceeds its allocation.");
            WriteBytes(caveAddr, cave);

            var patch = BuildRelativeJump(hookAddr, caveAddr, hookSize);
            WriteProtectedBytes(hookAddr, patch);

            _hooks[name] = new RuntimeDetour
            {
                Name = name,
                Address = hookAddr,
                DetourAddress = caveAddr,
                Size = caveSize,
                Original = original,
                Patch = patch,
            };
            _hookedAddresses.Add(hookAddr);
            L($"{name} detour installed. target=0x{hookAddr:X}, cave=0x{caveAddr:X}, {cave.Length}B");
            return caveAddr;
        }
    }

    /// <summary>
    /// Removes a detour installed with <see cref="InstallCustomDetour"/>: restores the
    /// original bytes first (no new entries into the cave), waits a few frames so a game
    /// thread that is still inside the cave can leave it, then frees the cave.
    /// </summary>
    public void RemoveDetour(string name)
    {
        RuntimeDetour? det;
        lock (_lock)
        {
            if (!_hooks.TryGetValue(name, out det)) return;
            _hooks.Remove(name);
            _hookedAddresses.Remove(det.Address);
            if (_handle == IntPtr.Zero || _process is not { HasExited: false }) return;
            try { WriteProtectedBytes(det.Address, det.Original); }
            catch (Exception ex) { L($"{name}: could not restore hook site: {ex.Message}"); return; }
        }
        Thread.Sleep(80);
        try { Native.VirtualFreeEx(_handle, new IntPtr((long)det.DetourAddress), UIntPtr.Zero, Native.MEM_RELEASE); }
        catch { /* leak the page rather than risk the game */ }
        L($"{name} detour removed.");
    }

    /// <summary>
    /// Start of the function containing <paramref name="addr"/>, from the module's
    /// exception directory (.pdata RUNTIME_FUNCTION table). 0 when not covered.
    /// Lets signature code verify that a match is a real function entry.
    /// </summary>
    public ulong FindFunctionStart(ulong addr)
    {
        try
        {
            var dos = ReadBytes(_mainBase, 0x40);
            if (dos.Length < 0x40 || dos[0] != (byte)'M' || dos[1] != (byte)'Z') return 0;
            var eLfanew = BitConverter.ToInt32(dos, 0x3C);
            var nt = ReadBytes(_mainBase + (ulong)eLfanew, 0x200);
            if (nt.Length < 0x200 || BitConverter.ToUInt32(nt, 0) != 0x4550) return 0;      // "PE\0\0"
            if (BitConverter.ToUInt16(nt, 24) != 0x20B) return 0;                              // PE32+
            const int dirException = 3;
            var excRva = BitConverter.ToUInt32(nt, 24 + 112 + dirException * 8);
            var excSize = BitConverter.ToUInt32(nt, 24 + 112 + dirException * 8 + 4);
            if (excRva == 0 || excSize < 12) return 0;
            var table = ReadBytes(_mainBase + excRva, (int)excSize);
            var rva = (uint)(addr - _mainBase);
            int lo = 0, hi = table.Length / 12 - 1;
            while (lo <= hi)
            {
                var mid = (lo + hi) / 2;
                var begin = BitConverter.ToUInt32(table, mid * 12);
                var end = BitConverter.ToUInt32(table, mid * 12 + 4);
                if (rva < begin) hi = mid - 1;
                else if (rva >= end) lo = mid + 1;
                else return _mainBase + begin;
            }
        }
        catch { /* fall through */ }
        return 0;
    }
    /// <summary>
    /// Returns the captured XP progression owner (RCX at AddTotalXP), or null.
    /// </summary>
    public ulong? GetCapturedXpOwner()
    {
        if (_xpOwnerStorageAddr == 0) return null;
        var ptr = ReadUInt64(_xpOwnerStorageAddr);
        return ptr != 0 ? ptr : null;
    }

    /// <summary>Address of the game's AddTotalXP(owner, amount) — for shellcode calls.</summary>
    public ulong XpAddFunction => _xpAddFunctionAddr;

    public bool EnsureXpHook(out string? error)
    {
        error = null;
        if (_xpHookInstalled) return true;
        if (!IsAttached) { error = "Not attached."; return false; }
        // Same rule as season/profile hooks: no .text patch without the CRC bypass.
        try { EnsureCrcBypass(); }
        catch (Exception ex) { error = $"CRC bypass: {ex.Message}"; return false; }
        try
        {
            var bytes = ReadBytes(_mainBase, _mainSize);
            if (bytes.Length == 0) { error = "Could not read main module."; return false; }
            InstallXpHook(bytes);
            if (!_xpHookInstalled) { error = "AddTotalXP site not found in this build."; return false; }
            return true;
        }
        catch (Exception ex)
        {
            error = $"XP hook install failed: {ex.Message}";
            return false;
        }
    }

    private void InstallXpHook(byte[] moduleBytes)
    {
        if (_xpHookInstalled) return;

        // AddTotalXP prologue; unique in v379/v382/v403. lea disp wildcarded.
        var sigStr = "48 89 5C 24 10 48 89 74 24 18 57 48 81 EC 90 00 00 00 8B FA 48 8B F1 " +
                     "48 8B 59 58 45 33 C9 41 B8 20 00 00 00 48 8D 15 ? ? ? ? 48 8D 4C 24 38";
        var pattern = Pattern.Parse(sigStr);
        int match = -1, count = 0;
        foreach (var off in Pattern.FindAll(moduleBytes, pattern, 16))
        {
            count++;
            if (match < 0) match = off;
        }
        if (count != 1)
        {
            L($"XP: refusing to hook — expected 1 AddTotalXP match, found {count}");
            return;
        }

        var hookAddr = _mainBase + (ulong)match;
        _xpAddFunctionAddr = hookAddr;
        L($"XP: AddTotalXP at 0x{hookAddr:X}");

        // Original first instruction is exactly 5 bytes (mov [rsp+0x10],rbx).
        // Cave: save RCX (the owner), re-execute it, jump back.
        const int caveSize = 0x20;
        const int storageOffset = 0x18;
        var caveAddr = AllocateNear(hookAddr, caveSize);
        var cave = new byte[caveSize];

        cave[0] = 0x48; cave[1] = 0x89; cave[2] = 0x0D; // MOV [rip+disp32],RCX
        BitConverter.GetBytes(storageOffset - 7).CopyTo(cave, 3);

        cave[7] = 0x48; cave[8] = 0x89; cave[9] = 0x5C; cave[10] = 0x24; cave[11] = 0x10; // mov [rsp+0x10],rbx

        var jmpBack = BuildRelativeJump(caveAddr + 12, hookAddr + 5, 5);
        Buffer.BlockCopy(jmpBack, 0, cave, 12, 5);

        WriteBytes(caveAddr, cave);
        _xpOwnerStorageAddr = caveAddr + storageOffset;

        var hookPatch = BuildRelativeJump(hookAddr, caveAddr, 5);
        var original = ReadBytes(hookAddr, 5);
        WriteProtectedBytes(hookAddr, hookPatch);

        _hooks["XpCapture"] = new RuntimeDetour
        {
            Name = "XpCapture",
            Address = hookAddr,
            DetourAddress = caveAddr,
            Size = caveSize,
            Original = original,
            Patch = hookPatch,
        };

        _xpHookInstalled = true;
        L($"XP hook installed. cave=0x{caveAddr:X}, owner-storage=0x{_xpOwnerStorageAddr:X}");
    }

    public bool   IsAddressHooked(ulong addr) => _hookedAddresses.Contains(addr);

    /// <summary>
    /// Installs the weather entity capture hook. Strictly opt-in (like the season
    /// hook). Uses multi-match on the rain getter body — all copies are hooked.
    /// </summary>
    public bool EnsureWeatherHook(out string? error)
    {
        error = null;
        if (_weatherHookInstalled) return true;
        if (!IsAttached) { error = "Not attached."; return false; }
        // Same rule as season/profile hooks: no .text patch without the CRC bypass.
        try { EnsureCrcBypass(); }
        catch (Exception ex) { error = $"CRC bypass: {ex.Message}"; return false; }
        try
        {
            var bytes = ReadBytes(_mainBase, _mainSize);
            if (bytes.Length == 0) { error = "Could not read main module."; return false; }
            InstallWeatherHook(bytes);
            if (!_weatherHookInstalled) { error = "Weather hook site not found in this build."; return false; }
            return true;
        }
        catch (Exception ex)
        {
            error = $"Weather hook install failed: {ex.Message}";
            return false;
        }
    }

    private void InstallWeatherHook(byte[] moduleBytes)
    {
        if (_weatherHookInstalled) return;

        // The rain getter: movss xmm0,[rcx+0x16C] (8 bytes, followed by ret).
        // Same multi-match approach as season — hook all copies.
        var sig = new byte[] { 0xF3, 0x0F, 0x10, 0x81, 0x6C, 0x01, 0x00, 0x00, 0xC3 };
        var matches = new List<int>();
        for (int i = 0x1000; i + sig.Length < moduleBytes.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < sig.Length; j++)
                if (moduleBytes[i + j] != sig[j]) { ok = false; break; }
            if (ok) matches.Add(i);
        }
        if (matches.Count == 0)
        {
            L("Weather: no rain getter matches found in this build.");
            return;
        }

        L($"Weather: found {matches.Count} rain getter cop{(matches.Count == 1 ? "y" : "ies")}, hooking all");

        const int caveSize = 0x20;
        const int storageOffset = 0x14;
        for (int idx = 0; idx < matches.Count && idx < 4; idx++)
        {
            var hookAddr = _mainBase + (ulong)matches[idx];

            var caveAddr = AllocateNear(hookAddr, caveSize);
            var storageAddr = caveAddr + storageOffset;
            _weatherEntityStorageAddrs.Add(storageAddr);

            var cave = new byte[caveSize];
            cave[0] = 0x48; cave[1] = 0x89; cave[2] = 0x0D; // MOV [rip+disp32],RCX
            BitConverter.GetBytes(storageOffset - 7).CopyTo(cave, 3);
            // re-execute: movss xmm0,[rcx+0x16C]
            cave[7] = 0xF3; cave[8] = 0x0F; cave[9] = 0x10; cave[10] = 0x81;
            cave[11] = 0x6C; cave[12] = 0x01; cave[13] = 0x00; cave[14] = 0x00;
            // ret
            cave[15] = 0xC3;

            WriteBytes(caveAddr, cave);

            var hookPatch = BuildRelativeJump(hookAddr, caveAddr, 9);
            var original = ReadBytes(hookAddr, 9);
            WriteProtectedBytes(hookAddr, hookPatch);

            _hooks[$"WeatherCapture{idx}"] = new RuntimeDetour
            {
                Name = $"WeatherCapture{idx}",
                Address = hookAddr,
                DetourAddress = caveAddr,
                Size = caveSize,
                Original = original,
                Patch = hookPatch,
            };

            L($"Weather hook [{idx}] installed @ 0x{hookAddr:X}, storage=0x{storageAddr:X}");
        }

        _weatherHookInstalled = true;
    }

    public void   LogPublic(string msg) => L(msg);

    public string DiagnosticsTail(int lines = 12)
        => string.Join("\n", Log.Skip(Math.Max(0, Log.Count - lines)));

    private void L(string msg)
    {
        lock (_lock) Log.Add(msg);
        _onLog?.Invoke(msg);
    }

    // ===== Attach =====

    public bool Attach(int pid)
    {
        // Full reset of any previous session's state. Hooks, caves, the CRC pointer
        // and the season-capture flag all belong to the OLD process address space.
        // A game that dies and relaunches between our 2s polls never triggers the
        // game-lost cleanup, so Attach must self-clean — otherwise stale state
        // (e.g. the season hook flag, or _hooks entries) points into the wrong
        // process and season clicks fail forever (#195).
        if (_handle != IntPtr.Zero)
            Detach();

        Native.EnableDebugPrivilege();
        var h = Native.OpenProcess(Native.PROCESS_ALL_ACCESS, false, (uint)pid);
        if (h == IntPtr.Zero)
        {
            L($"OpenProcess({pid}) failed.");
            return false;
        }

        Process p;
        try { p = Process.GetProcessById(pid); }
        catch (Exception ex) { Native.CloseHandle(h); L($"GetProcessById failed: {ex.Message}"); return false; }

        // Try managed MainModule first (fast path for Steam build)
        try
        {
            var m = p.MainModule!;
            _handle = h;
            _process = p;
            _mainBase = (ulong)m.BaseAddress.ToInt64();
            _mainSize = m.ModuleMemorySize;
            L($"Attached PID {pid} (managed path). base=0x{_mainBase:X}, size={_mainSize}B, file={m.FileName}");
            return true;
        }
        catch (Exception managedEx)
        {
            // UWP / sandboxed processes throw AccessDenied here — fall back to Win32 EnumProcessModulesEx
            L($"MainModule denied (likely UWP/Xbox build) — falling back to native EnumProcessModulesEx. Detail: {managedEx.Message}");
        }

        var found = Native.FindMainModule(h, "ForzaHorizon6");
        if (found is null)
        {
            Native.CloseHandle(h);
            L("Native EnumProcessModulesEx also failed — cannot locate ForzaHorizon6 main module. Are you running as admin?");
            return false;
        }

        _handle = h;
        _process = p;
        _mainBase = (ulong)found.Value.Base.ToInt64();
        _mainSize = (int)found.Value.Size;
        L($"Attached PID {pid} (UWP fallback). base=0x{_mainBase:X}, size={_mainSize}B, file={found.Value.Path}");
        return true;
    }

    /// <summary>
    /// Cleanly detach: restore hook bytes, free caves, restore CRC pointer,
    /// stop timer, close process handle.
    /// </summary>
    public void Detach()
    {
        StopCrcTimer();
        RestoreCrcPointer();

        RestoreRuntimeProfileHooks();

        // Reset per-process state — capture flags must not survive a game restart,
        // or the next game process silently skips installation (#195).
        _weatherHookInstalled = false;
        _weatherEntityStorageAddrs.Clear();
        _xpHookInstalled = false;
        _xpOwnerStorageAddr = 0;
        _xpAddFunctionAddr = 0;

        _preResolved = false;
        _preResolvedTargets.Clear();

        _process?.Dispose();
        _process = null;
        if (_handle != IntPtr.Zero) Native.CloseHandle(_handle);
        _handle = IntPtr.Zero;
        _mainBase = 0;
        _mainSize = 0;
        _crcBypassActive = false;
    }

    public void Dispose() => Detach();

    private void RestoreRuntimeProfileHooks()
    {
        lock (_lock)
        {
            // If the game process is already gone there is nothing to restore into —
            // the addresses belong to a dead address space. Just drop the registrations.
            var alive = _process is { HasExited: false };
            foreach (var det in _hooks.Values)
            {
                try
                {
                    if (_handle != IntPtr.Zero && alive)
                    {
                        WriteProtectedBytes(det.Address, det.Original);
                        if (det.DetourAddress != 0)
                            Native.VirtualFreeEx(_handle, new IntPtr((long)det.DetourAddress), UIntPtr.Zero, Native.MEM_RELEASE);
                    }
                }
                catch (Exception ex) { L($"Could not restore {det.Name}: {ex.Message}"); }
            }
            if (_hooks.Count > 0)
                L(alive
                    ? $"Restored {_hooks.Count} runtime hook(s)."
                    : $"Dropped {_hooks.Count} runtime hook(s) from the previous game process (nothing to restore into).");
            _hooks.Clear();
            _hookedAddresses.Clear();
        }
    }

    // ===== Profile hooks (Credits / Wheelspins / SP / Drift / NoSkillBreak / Sell) =====

    public bool ApplyProfile(RuntimeProfileFeature feature, int value, bool enabled, out string? error)
    {
        error = null;
        if (!IsAttached) { error = "Not attached."; return false; }
        var desc = ProfileFeatureCatalog.Get(feature);
        if (desc.BrokenNote is not null)
        {
            error = $"{desc.Name} is disabled: {desc.BrokenNote}";
            return false;
        }

        return ApplyProfileLegacy(feature, value, enabled, out error);
    }

    private bool ApplyProfileLegacy(RuntimeProfileFeature feature, int value, bool enabled, out string? error)
    {
        error = null;
        var desc = ProfileFeatureCatalog.Get(feature);
        try
        {
            RuntimeDetour det;
            lock (_lock)
            {
                if (!enabled)
                {
                    if (!_hooks.TryGetValue(desc.Key, out det!))
                    {
                        L($"{desc.Name} hook already OFF.");
                        return true;
                    }
                }
                else
                {
                    det = EnsureProfileHook(desc);
                }
            }
            WriteByte(det.DetourAddress + (ulong)desc.ToggleOffset, (byte)(enabled ? 1 : 0));
            if (desc.ValueOffset >= 0)
                WriteInt32(det.DetourAddress + (ulong)desc.ValueOffset, value);
            L($"{desc.Name} {(enabled ? "ENABLED" : "DISABLED")} @ detour 0x{det.DetourAddress:X}, value={value}.");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            L($"{desc.Name} apply failed: {ex.Message}");
            return false;
        }
    }

    public bool UpdateValue(RuntimeProfileFeature feature, int value, out string? error)
    {
        error = null;
        var desc = ProfileFeatureCatalog.Get(feature);
        if (desc.BrokenNote is not null)
        {
            error = $"{desc.Name} is disabled: {desc.BrokenNote}";
            return false;
        }

        lock (_lock)
        {
            if (!_hooks.TryGetValue(desc.Key, out var det))
            {
                error = $"{desc.Name} is not enabled.";
                return false;
            }
            if (desc.ValueOffset < 0)
            {
                L($"{desc.Name}: NOP-sled does not support value updates (value={value} ignored, cheat remains active)");
                return true;
            }
            try
            {
                WriteInt32(det.DetourAddress + (ulong)desc.ValueOffset, value);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }

    private RuntimeDetour EnsureProfileHook(RuntimeProfileHookDescriptor desc)
    {
        if (_hooks.TryGetValue(desc.Key, out var existing)) return existing;

        EnsureCrcBypass();
        EnsurePreResolved();

        ulong hookAddr;
        if (_preResolvedTargets.TryGetValue(desc.Key, out var cached))
        {
            hookAddr = cached;
            L($"{desc.Name}: using pre-resolved target at 0x{hookAddr:X}");
        }
        else
        {
            L($"{desc.Name}: scanning sig '{desc.Signature}'...");
            var moduleBytes = ReadBytes(_mainBase, _mainSize);
            if (moduleBytes.Length == 0)
                throw new InvalidOperationException($"Could not read main module for {desc.Name} scan.");
            hookAddr = FindProfileHookTarget(moduleBytes, desc);
        }

        var det = CreateRuntimeDetour(desc, hookAddr);
        _hooks[desc.Key] = det;
        L($"{desc.Name} detour installed. target=0x{hookAddr:X}, cave=0x{det.DetourAddress:X}, size={det.Size}B");
        return det;
    }

    /// <summary>
    /// Pre-resolves all profile hook targets before any hooks are installed.
    /// This prevents NOP-sleds from corrupting nearby signatures (e.g., Wheelspins
    /// and SkillPoints share the same function and their instructions are 12 bytes apart).
    /// </summary>
    private void EnsurePreResolved()
    {
        if (_preResolved) return;
        _preResolved = true;

        var moduleBytes = ReadBytes(_mainBase, _mainSize);
        if (moduleBytes.Length == 0) return;

        L("Pre-resolving all hook targets (no hooks installed yet)...");
        foreach (RuntimeProfileFeature feature in Enum.GetValues<RuntimeProfileFeature>())
        {
            var desc = ProfileFeatureCatalog.Get(feature);
            if (desc.BrokenNote != null) continue;
            if (_preResolvedTargets.ContainsKey(desc.Key)) continue;

            try
            {
                var addr = FindProfileHookTarget(moduleBytes, desc);
                _preResolvedTargets[desc.Key] = addr;
            }
            catch { /* some features may not match, that's OK */ }
        }
        L($"Pre-resolved {_preResolvedTargets.Count} hook targets");
    }

    /// <summary>
    /// Multi-candidate signature resolver. Tries primary signature first, then
    /// AltSignatures as fallbacks. A candidate is accepted only when the bytes at
    /// the hook site equal ExpectedOriginal (exact match) — no dynamic fallback,
    /// so an updated build refuses cleanly instead of patching the wrong site.
    /// Deduplicates against addresses already claimed by other cheats.
    /// </summary>
    private ulong FindProfileHookTarget(byte[] moduleBytes, RuntimeProfileHookDescriptor desc)
    {
        var sigs = new List<(string Sig, string Label)> { (desc.Signature, "primary") };
        foreach (var alt in desc.AltSignatures)
            sigs.Add((alt, "alt"));

        bool anyMatchFound = false;
        bool anyTargetPatched = false;
        string firstMismatchSample = string.Empty;

        foreach (var (sig, label) in sigs)
        {
            var pattern = Pattern.Parse(sig);
            foreach (var off in Pattern.FindAll(moduleBytes, pattern, 128))
            {
                anyMatchFound = true;

                ulong hookAddr;
                if (desc.ResolveCallTarget)
                {
                    var callAddr = _mainBase + (ulong)off;
                    var head = ReadBytes(callAddr, 5);
                    if (head.Length < 5 || head[0] != 0xE8) continue;
                    var rel = BitConverter.ToInt32(head, 1);
                    hookAddr = (ulong)((long)(callAddr + 5) + rel + desc.CallTargetOffset);
                }
                else
                {
                    hookAddr = (ulong)((long)_mainBase + off + desc.MatchOffset);
                }

                // Skip addresses already claimed by another cheat
                if (_hookedAddresses.Contains(hookAddr))
                {
                    L($"{desc.Name}: match at 0x{hookAddr:X} ({label}) — address already used by another cheat, skipping");
                    continue;
                }

                var original = ReadBytes(hookAddr, desc.HookSize);
                if (original.Length < desc.HookSize) continue;

                if (original.Length > 0 && original[0] == 0xE9)
                {
                    L($"{desc.Name}: match at 0x{hookAddr:X} ({label}) — already patched (JMP), skipping");
                    anyTargetPatched = true;
                    continue;
                }


                // Validate struct offset range for MOV/ADD [rbx+disp32] patterns
                if (original.Length >= 6 && (original[0] == 0x89 || original[0] == 0x01) && original[1] == 0x83)
                {
                    var structOff = BitConverter.ToInt32(original, 2);
                    if (structOff < 0 || structOff > 0x2000)
                    {
                        L($"{desc.Name}: match at 0x{hookAddr:X} ({label}) — struct offset 0x{structOff:X} out of range, skipping");
                        continue;
                    }
                }

                if (BytesStartWith(original, desc.ExpectedOriginal))
                {
                    L($"{desc.Name}: match at 0x{hookAddr:X} ({label}) — exact{ExtractStructOffset(original, desc)}");
                    _hookedAddresses.Add(hookAddr);
                    return hookAddr;
                }

                if (string.IsNullOrEmpty(firstMismatchSample))
                    firstMismatchSample = $"expected {FormatBytes(desc.ExpectedOriginal)}, got {FormatBytes(original)}";
            }
        }

        if (!anyMatchFound)
            throw new InvalidOperationException($"{desc.Name} signature was not found (tried primary + {desc.AltSignatures.Length} alts).\nPrimary: {desc.Signature}");
        if (anyTargetPatched)
            throw new InvalidOperationException($"{desc.Name} hook target already patched by another tool. Close other trainers and retry.");
        throw new InvalidOperationException($"{desc.Name} hook target bytes mismatch (FH6 may have updated; exact match required). {firstMismatchSample}");
    }

    /// <summary>
    /// In-place context search — scans moduleBytes[matchOffset-256..matchOffset]
    /// without allocating a sub-array.
    /// <summary>
    /// Extracts the struct displacement from MOV/ADD [rbx+disp32], eax instructions
    /// for diagnostic logging. Returns empty string if not applicable.
    /// </summary>
    private static string ExtractStructOffset(byte[] original, RuntimeProfileHookDescriptor desc)
    {
        if (original.Length < 6) return "";
        // 89 83 XX XX XX XX = MOV [rbx+disp32], eax
        // 01 83 XX XX XX XX = ADD [rbx+disp32], eax
        if ((original[0] == 0x89 || original[0] == 0x01) && original[1] == 0x83)
        {
            var offset = BitConverter.ToInt32(original, 2);
            return $" [rbx+0x{offset:X}]";
        }
        return "";
    }

    private RuntimeDetour CreateRuntimeDetour(RuntimeProfileHookDescriptor desc, ulong hookAddr)
    {
        var original = ReadBytes(hookAddr, desc.HookSize);

        // NOP-sled mode: no code cave, just overwrite target bytes directly.
        // Asm contains the replacement bytes (all NOPs), OriginalRegions is empty.
        if (desc.OriginalRegions.Length == 0)
        {
            var nopPatch = desc.Asm;
            WriteProtectedBytes(hookAddr, nopPatch);
            return new RuntimeDetour
            {
                Name = desc.Name,
                Address = hookAddr,
                DetourAddress = hookAddr, // no cave — point at hook site
                Size = nopPatch.Length,
                Original = original,
                Patch = nopPatch,
            };
        }

        // Code-cave mode (original approach for complex hooks)
        var patchedAsm = (byte[])desc.Asm.Clone();

        foreach (var (asmOffset, origOffset, length) in desc.OriginalRegions)
        {
            if (asmOffset + length <= patchedAsm.Length && origOffset + length <= original.Length)
            {
                for (var i = 0; i < length; i++)
                    patchedAsm[asmOffset + i] = original[origOffset + i];
            }
        }

        var caveSize = Math.Max(
            patchedAsm.Length + 5,
            Math.Max(desc.ToggleOffset + 1, desc.ValueOffset >= 0 ? desc.ValueOffset + 4 : 0));

        var caveAddr = AllocateNear(hookAddr, caveSize);
        var cave = new byte[caveSize];
        Buffer.BlockCopy(patchedAsm, 0, cave, 0, patchedAsm.Length);
        var jmpBack = BuildRelativeJump(caveAddr + (ulong)patchedAsm.Length, hookAddr + (ulong)desc.HookSize, 5);
        Buffer.BlockCopy(jmpBack, 0, cave, patchedAsm.Length, jmpBack.Length);
        WriteBytes(caveAddr, cave);

        var hookPatch = BuildRelativeJump(hookAddr, caveAddr, desc.HookSize);
        WriteProtectedBytes(hookAddr, hookPatch);

        return new RuntimeDetour
        {
            Name = desc.Name,
            Address = hookAddr,
            DetourAddress = caveAddr,
            Size = caveSize,
            Original = original,
            Patch = hookPatch,
        };
    }

    private void EnsureCrcBypass()
    {
        if (_crcBypassActive) return;
        if (_mainBase == 0 || _mainSize <= 0)
            throw new InvalidOperationException("Main module not captured.");

        var bytes = ReadBytes(_mainBase, _mainSize);
        if (bytes.Length == 0) throw new InvalidOperationException("Could not read main module for CRC bypass.");

        var retOff = FindFirstExecutablePatternOffset(bytes, "C3");
        if (retOff < 0) throw new InvalidOperationException("CRC bypass ret-stub not found.");

        var crcOff = FindFirstPatternOffset(bytes, "48 8B D9 48 8D 05 ? ? ? ? 48 89 01 E8 ? ? ? ? 48 8B CB 48 83 C4 20 5B E9");
        if (crcOff < 0) throw new InvalidOperationException("CRC bypass signature not found (FH6 likely updated).");

        var sigAddr = _mainBase + (ulong)crcOff;
        var leaStart = sigAddr + 3;
        var leaDisp = ReadInt32(leaStart + 3);
        var tableBase = leaStart + 7 + (ulong)leaDisp;
        var fnPtrAddr = tableBase + 48;
        var origFnPtr = ReadUInt64(fnPtrAddr);
        if (origFnPtr == 0) throw new InvalidOperationException("CRC function pointer is zero.");
        var retAddr = _mainBase + (ulong)retOff;

        WriteUInt64(fnPtrAddr, retAddr);
        _crcFunctionPointerAddress = fnPtrAddr;
        _crcOriginalPointer = origFnPtr;
        _crcRetAddress = retAddr;
        _crcBypassActive = true;
        StartCrcTimer();
        L($"CRC bypass armed. ptr=0x{fnPtrAddr:X}, ret=0x{retAddr:X}");
    }

    private void StartCrcTimer()
    {
        _crcTimer ??= new Timer(CrcTimerTick, null, 10_000, 10_000);
    }

    private void StopCrcTimer()
    {
        var t = _crcTimer;
        _crcTimer = null;
        try { t?.Dispose(); } catch { }
    }

    private void CrcTimerTick(object? _)
    {
        if (Interlocked.Exchange(ref _crcTimerRunning, 1) == 1) return;
        try
        {
            lock (_lock)
            {
                if (!_crcBypassActive || _handle == IntPtr.Zero || _process?.HasExited != false) return;
                try
                {
                    foreach (var det in _hooks.Values)
                        WriteProtectedBytes(det.Address, det.Original);
                    WriteUInt64(_crcFunctionPointerAddress, _crcOriginalPointer);
                }
                catch (Exception ex) { L($"CRC phase-1 (restore) failed: {ex.Message}"); return; }
            }

            Thread.Sleep(1000);

            lock (_lock)
            {
                if (!_crcBypassActive || _handle == IntPtr.Zero || _process?.HasExited != false) return;
                try
                {
                    WriteUInt64(_crcFunctionPointerAddress, _crcRetAddress);
                    foreach (var det in _hooks.Values)
                        WriteProtectedBytes(det.Address, det.Patch);
                }
                catch (Exception ex) { L($"CRC phase-2 (re-apply) failed: {ex.Message}"); }
            }
        }
        catch (Exception ex) { L($"CRC tick uncaught: {ex.Message}"); }
        finally { Interlocked.Exchange(ref _crcTimerRunning, 0); }
    }

    private void RestoreCrcPointer()
    {
        if (!_crcBypassActive || _crcFunctionPointerAddress == 0 || _crcOriginalPointer == 0 || _handle == IntPtr.Zero)
            return;
        // Nothing to restore into a dead process — just drop the state.
        if (_process is not { HasExited: false })
        {
            _crcBypassActive = false;
            return;
        }
        try { WriteUInt64(_crcFunctionPointerAddress, _crcOriginalPointer); }
        catch (Exception ex) { L($"CRC pointer restore failed: {ex.Message}"); }
        _crcBypassActive = false;
    }

    // ===== low-level read/write/alloc =====

    private byte[] ReadBytes(ulong address, int length)
    {
        if (length <= 0) return [];
        var buf = new byte[length];
        if (!Native.ReadProcessMemory(_handle, new IntPtr((long)address), buf, (UIntPtr)(ulong)length, out var read))
            return [];
        var got = (int)(uint)read;
        if (got == length) return buf;
        if (got <= 0) return [];
        var trimmed = new byte[got];
        Buffer.BlockCopy(buf, 0, trimmed, 0, got);
        return trimmed;
    }

    private ulong ReadUInt64(ulong address)
    {
        var b = ReadBytes(address, 8);
        return b.Length < 8 ? 0UL : BitConverter.ToUInt64(b, 0);
    }

    private int ReadInt32(ulong address)
    {
        var b = ReadBytes(address, 4);
        return b.Length < 4 ? 0 : BitConverter.ToInt32(b, 0);
    }

    private void WriteBytes(ulong address, byte[] data)
    {
        if (!Native.WriteProcessMemory(_handle, new IntPtr((long)address), data, (UIntPtr)(ulong)data.Length, out var written)
            || (ulong)written != (ulong)data.Length)
            throw new InvalidOperationException($"WriteProcessMemory @ 0x{address:X} failed.");
    }

    private void WriteByte(ulong address, byte value) => WriteBytes(address, [value]);
    private void WriteInt32(ulong address, int value) => WriteBytes(address, BitConverter.GetBytes(value));
    private void WriteUInt64(ulong address, ulong value) => WriteProtectedBytes(address, BitConverter.GetBytes(value));

    private void WriteProtectedBytes(ulong address, byte[] data)
    {
        if (!Native.VirtualProtectEx(_handle, new IntPtr((long)address), (UIntPtr)(ulong)data.Length,
                Native.PAGE_EXECUTE_READWRITE, out var old))
            throw new InvalidOperationException("VirtualProtectEx failed.");
        try { WriteBytes(address, data); }
        finally { Native.VirtualProtectEx(_handle, new IntPtr((long)address), (UIntPtr)(ulong)data.Length, old, out _); }
    }

    private ulong AllocateNear(ulong target, int size)
    {
        var page = target & 0xFFFF_FFFF_FFFF_0000UL;
        for (ulong step = 0; step <= 0x7000_0000UL; step += 0x1_0000UL)
        {
            if (page > step)
            {
                var r = TryAllocateAt(page - step, size, target);
                if (r != 0) return r;
            }
            var up = page + step;
            if (up < 0x0000_7FFF_FFFE_0000UL)
            {
                var r = TryAllocateAt(up, size, target);
                if (r != 0) return r;
            }
        }
        throw new InvalidOperationException($"Could not allocate detour near 0x{target:X}.");
    }

    private ulong TryAllocateAt(ulong address, int size, ulong target)
    {
        if (address == 0) return 0;
        var p = Native.VirtualAllocEx(_handle, new IntPtr((long)address),
            (UIntPtr)(ulong)Math.Max(size, 4096),
            Native.MEM_COMMIT | Native.MEM_RESERVE,
            Native.PAGE_EXECUTE_READWRITE);
        if (p == IntPtr.Zero) return 0;
        var got = (ulong)p.ToInt64();
        if (RelativeJumpFits(target, got) && RelativeJumpFits(got, target)) return got;
        Native.VirtualFreeEx(_handle, p, UIntPtr.Zero, Native.MEM_RELEASE);
        return 0;
    }

    // ===== pattern + jump helpers =====

    private int FindFirstPatternOffset(byte[] data, string sig)
    {
        var pat = Pattern.Parse(sig);
        foreach (var o in Pattern.FindAll(data, pat, 1)) return o;
        return -1;
    }

    /// <summary>
    /// Finds the first signature match whose address lies in an executable region.
    /// Used to locate a bare 0xC3 (ret) stub in .text for the CRC vtable swap.
    /// </summary>
    private int FindFirstExecutablePatternOffset(byte[] data, string sig)
    {
        var pat = Pattern.Parse(sig);
        foreach (var o in Pattern.FindAll(data, pat, 4096))
        {
            if (IsExecutableAddress(_mainBase + (ulong)o))
                return o;
        }
        return -1;
    }

    private bool IsExecutableAddress(ulong addr)
    {
        if (Native.VirtualQueryEx(_handle, (UIntPtr)addr, out var mbi,
                (UIntPtr)(ulong)System.Runtime.InteropServices.Marshal.SizeOf<Native.MemoryBasicInformation64>()) == UIntPtr.Zero)
            return false;
        return Native.IsExecutable(mbi.Protect);
    }

    private static byte[] BuildRelativeJump(ulong from, ulong to, int length)
    {
        if (length < 5) throw new InvalidOperationException("Jump length < 5.");
        var diff = (long)(to - (from + 5));
        if (diff < int.MinValue || diff > int.MaxValue)
            throw new InvalidOperationException("Jump out of int32 range.");
        var arr = new byte[length];
        arr[0] = 0xE9;
        Buffer.BlockCopy(BitConverter.GetBytes((int)diff), 0, arr, 1, 4);
        for (var i = 5; i < arr.Length; i++) arr[i] = 0x90;
        return arr;
    }

    private static bool RelativeJumpFits(ulong from, ulong to)
    {
        var d = (long)(to - (from + 5));
        return d >= int.MinValue && d <= int.MaxValue;
    }

    private static bool BytesStartWith(byte[] current, byte[] expected)
    {
        if (expected.Length == 0) return true;
        if (current.Length < expected.Length) return false;
        for (var i = 0; i < expected.Length; i++)
            if (current[i] != expected[i]) return false;
        return true;
    }

    private static string FormatBytes(byte[] b) => string.Join(" ", b.Select(x => x.ToString("X2")));
}
