using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
using FH6Mod.Cheats.RuntimeHook;

namespace FH6Mod.Cheats.Season;

/// <summary>
/// Switches the in-game season by driving the game's own season API.
///
/// Reverse-engineered on v6.440.853.0 from a decrypted memory dump:
///
///   * The season system is <c>Seasons::SeasonManagerClient</c>, a heap singleton whose
///     pointer lives in a .data global. Season enum: 0 Spring, 1 Summer, 2 Autumn,
///     3 Winter, 4 = Any / not loaded.
///   * Its season fields are guarded values: the game only reads them through
///     lock/unlock helpers that register each field in a global protection table, and a
///     plain ReadProcessMemory of the slot returns garbage. So every read goes through the
///     game's own getters (GetCurrentSeasonType, GetSeason(visual), HasForcedVisualSeason)
///     executed on the game thread.
///   * The script-bound entity method <c>ForceVisualSeason(season)</c> is just:
///       if (!HasForcedVisualSeason(mgr)) saved = *GetClockOffset(mgr, &amp;tmp);
///       now = GetClockTime(mgr, &amp;tmp);  SetVisualSeason(mgr, season, now);
///     and <c>RevertVisualSeason()</c> is: SetClockOffset(mgr, saved); RevertVisualSeason(mgr, 0).
///     SetVisualSeason installs the override instance and synchronously notifies every
///     season listener (weather script reload, lighting/particle/material republish each
///     frame) — the same path EventLab/showcases use, so visuals change without a reload.
///   * Those calls take the manager's locks and walk listeners that touch world systems,
///     so they must run on the game thread. We hook the entry of the manager's per-frame
///     tick (<c>FinalizeNaturalRollover</c>, called once per engine tick with rcx =
///     manager) with a cave that executes whatever the trainer queued in a "pending" slot
///     (query / force / revert) and then runs the original prologue.
///   * The hook is TRANSIENT: installed for one request and removed right after it has
///     been executed. A hot per-frame hook that outlives the trainer (crash, task kill) is
///     caught by the game's integrity check and kills the game, so nothing is left behind.
///
/// All addresses are resolved by signature at runtime and cross-checked (both script
/// bindings must agree on the manager global; every call target must be a function entry;
/// the hook function must reference its own log string). If anything does not line up on
/// a new game build the feature refuses with a message instead of patching a guess.
/// </summary>
public sealed class SeasonChanger : IDisposable
{
    public enum FHSeason { Spring = 0, Summer = 1, Autumn = 2, Winter = 3 }
    /// <summary>Request value meaning "drop the forced season, back to the schedule".</summary>
    public const int Revert = 4;
    private const int CmdQuery = 100;

    public sealed record Status(int NaturalSeason, int EffectiveSeason, bool Forced, int State)
    {
        /// <summary>Schedule loaded and the player is in the world.</summary>
        public bool Ready => NaturalSeason is >= 0 and <= 3;
        /// <summary>A season transition / track swap is in flight — do not poke the manager.</summary>
        public bool Transitioning => State is 5 or 6 or 7;
    }

    // ---- v440.853 ----
    private const int OffState = 0x160;  // plain int state machine (3/4 idle, 5/6/7 transition); heuristic only

    // Script binding "ForceVisualSeason": cmp edx,4 / je ; ... mov rcx,[mgr] ; call HasForced ;
    // test al,al ; jne ; mov rcx,[mgr] ; lea rdx,[rsp+..] ; call GetClockOffset ; mov rcx,[rax] ;
    // mov [rbx+..],rcx ; mov rbx,[mgr] ; lea rdx,[rsp+..] ; mov rcx,rbx ; call GetClockTime ;
    // mov r8,rax ; mov edx,edi ; mov rcx,rbx ; call SetVisualSeason
    private const string SigForceBinding =
        "83 FA 04 74 ? 48 89 5C 24 08 57 48 83 EC 20 48 8B D9 8B FA 48 8B 0D ? ? ? ? E8 ? ? ? ? 84 C0 75 ? " +
        "48 8B 0D ? ? ? ? 48 8D 54 24 ? E8 ? ? ? ? 48 8B 08 48 89 8B ? ? ? ? 48 8B 1D ? ? ? ? 48 8D 54 24 ? " +
        "48 8B CB E8 ? ? ? ? 4C 8B C0 8B D7 48 8B CB E8";
    private const int ForceMgrMov = 0x14, ForceCallHasForced = 0x1B, ForceCallGetOffset = 0x30, ForceCallGetClock = 0x4E, ForceCallSetVisual = 0x5B;

    // Script binding "RevertVisualSeason": push rbx ; sub rsp,20 ; mov rdx,[rcx+..] ; mov rbx,rcx ;
    // mov rcx,[mgr] ; call SetClockOffset ; mov rcx,[mgr] ; xor edx,edx ; call RevertVisualSeason ;
    // mov qword [rbx+..],0 ; add rsp,20 ; pop rbx ; ret
    private const string SigRevertBinding =
        "40 53 48 83 EC 20 48 8B 91 ? ? ? ? 48 8B D9 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? 33 D2 E8 ? ? ? ? " +
        "48 C7 83 ? ? ? ? 00 00 00 00 48 83 C4 20 5B C3";
    private const int RevertMgrMov = 0x10, RevertCallSetOffset = 0x17, RevertCallRevert = 0x25;

    // SeasonManager::GetSeason(this, bool visual): returns 4 while the schedule asset is not loaded,
    // else the type of the instance picked by the selector (forced override first).
    private const string SigGetSeason =
        "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 0F B6 FA 48 81 C1 ? ? 00 00 E8 ? ? ? ? 84 C0 75 ? B8 04 00 00 00";

    // SeasonManager::GetCurrentSeasonType(this): natural instance type (4 when invalid), under its lock.
    private const string SigGetSeasonType =
        "40 57 48 83 EC 20 80 B9 ? ? 00 00 00 48 8B F9 74 ? 48 8B 89 ? ? 00 00 33 D2 48 89 5C 24 30 E8 ? ? ? ? " +
        "48 8B 8F ? ? 00 00 33 D2 8B 9F ? ? 00 00 E8";

    // Seasons::SeasonManagerBase::FinalizeNaturalRollover prologue (per-frame tick, rcx = manager).
    private const string SigRollover =
        "48 89 5C 24 20 55 56 57 41 56 41 57 48 8B EC 48 81 EC 80 00 00 00 4C 8B F1 80 B9 ? ? ? ? 00 0F 94 C2 48 81 C1 ? ? ? ? E8";
    // Same site with the first 5 bytes (our hook) wildcarded — to recognise a leftover hook.
    private const string SigRolloverHooked =
        "? ? ? ? ? 55 56 57 41 56 41 57 48 8B EC 48 81 EC 80 00 00 00 4C 8B F1 80 B9 ? ? ? ? 00 0F 94 C2 48 81 C1 ? ? ? ? E8";
    private const string RolloverLogString = "Seasons::SeasonManagerBase::FinalizeNaturalRollover";
    private const int HookSize = 5;                      // mov [rsp+0x20],rbx
    private static readonly byte[] HookExpected = [0x48, 0x89, 0x5C, 0x24, 0x20];
    private const string DetourName = "SeasonTick";

    private readonly RuntimeHookEngine _engine;
    private readonly object _lock = new();
    private readonly Timer _holdTimer;
    private int _holdBusy;

    // resolved per game process
    private bool _resolved;
    private ulong _mgrGlobal, _fnHasForced, _fnGetOffset, _fnGetClockTime, _fnSetVisualSeason, _fnSetOffset, _fnRevert;
    private ulong _fnGetSeason, _fnGetSeasonType, _hookSite;
    private int _offForcedFlag;
    private ulong _pendingAddr, _doneAddr, _qNaturalAddr, _qEffectiveAddr, _qForcedAddr;
    private bool _warnedObject;

    // user intent
    private int? _desired;
    private volatile bool _hold;
    private DateTime _lastApplyUtc = DateTime.MinValue;

    public SeasonChanger(RuntimeHookEngine engine)
    {
        _engine = engine;
        _holdTimer = new Timer(HoldTick, null, 5000, 5000);
    }

    /// <summary>Keep re-applying the chosen season after track swaps / fast travel.</summary>
    public bool Hold { get => _hold; set => _hold = value; }
    public int? DesiredSeason => _desired;
    public bool IsResolved => _resolved;

    public static string SeasonName(int? season) => season switch
    {
        0 => "Spring", 1 => "Summer", 2 => "Autumn", 3 => "Winter", 4 => "Any", null => "none", _ => $"Unknown({season})",
    };

    // =====================================================================================
    // Public API
    // =====================================================================================

    /// <summary>
    /// Queries the manager through the game's own getters. With <paramref name="allowHook"/>
    /// false (status on attach) nothing is installed and the result is null.
    /// </summary>
    public Status? ReadStatusSafe(bool allowHook)
    {
        lock (_lock)
        {
            try
            {
                if (!_engine.IsAttached) return null;
                if (!Resolve(out _)) return null;
                if (!allowHook) return null;
                if (ReadManager() == 0) return null;
                return WithHook(() => Query(out _), out _);
            }
            catch (Exception ex)
            {
                _engine.LogPublic($"Season: status read failed: {ex.Message}");
                return null;
            }
        }
    }

    public string DescribeStatus(bool allowHook)
    {
        lock (_lock)
        {
            if (!_engine.IsAttached) return "not attached";
            if (!Resolve(out var err)) return err ?? "not resolved on this build";
            if (!allowHook) return "resolved on this build — press Refresh in the Season card to query the game";
        }
        var st = ReadStatusSafe(true);
        return st is null ? "manager not available (not in the world yet?)" : Describe(st);
    }

    /// <summary>
    /// Switches to <paramref name="season"/> (0-3) or reverts to the schedule (<see cref="Revert"/>).
    /// Blocks until the game thread has executed the request (a few hundred ms).
    /// </summary>
    public bool Apply(int season, out string? error)
    {
        error = null;
        if (season is < 0 or > Revert) { error = "Invalid season."; return false; }
        lock (_lock)
        {
            if (!_engine.IsAttached) { error = "Not attached."; return false; }
            if (!Resolve(out error)) return false;
            if (ReadManager() == 0)
            {
                error = "The game has not created its season manager yet — load into the world first.";
                return false;
            }

            string? innerError = null;
            var ok = WithHook(() =>
            {
                var before = Query(out var qErr);
                if (before is null) { innerError = qErr; return false; }
                if (season == Revert)
                {
                    _desired = null;
                    if (!before.Forced) { _engine.LogPublic("Season: no forced season active, nothing to revert."); return true; }
                }
                else if (!before.Ready)
                {
                    innerError = "Season schedule not loaded yet (the game reports 'Any'). Load fully into the world, then try again.";
                    return false;
                }
                else if (before.Transitioning)
                {
                    innerError = $"A season/track transition is in progress (state {before.State}). Wait a moment and try again.";
                    return false;
                }

                _engine.LogPublic($"Season: request {(season == Revert ? "revert" : SeasonName(season))} (before: {Describe(before)})");
                if (!RunOnGameThread(season, 3000, out var runErr)) { innerError = runErr; return false; }
                Thread.Sleep(40);
                var after = Query(out qErr);
                _lastApplyUtc = DateTime.UtcNow;
                if (after is null) { innerError = qErr; return false; }

                if (season == Revert)
                {
                    var good = !after.Forced;
                    _engine.LogPublic($"Season: revert {(good ? "OK" : "did not clear the override")} (after: {Describe(after)})");
                    if (!good) innerError = "The game ran the revert but the forced season is still set. Try again in free roam.";
                    return good;
                }
                _desired = season;
                var applied = after.Forced && after.EffectiveSeason == season;
                _engine.LogPublic($"Season: switch to {SeasonName(season)} {(applied ? "OK" : "NOT applied")} (after: {Describe(after)})");
                if (!applied)
                    innerError = $"The game accepted the request but did not switch (now {Describe(after)}). " +
                                 "Its season schedule may not contain that season in the upcoming slices — try another season or reload into the world.";
                return applied;
            }, out var hookErr);
            error = innerError ?? hookErr;
            return ok;
        }
    }

    /// <summary>Drop per-process state. The engine restores any live hook itself on detach.</summary>
    public void Reset()
    {
        lock (_lock)
        {
            _resolved = false;
            _mgrGlobal = _fnHasForced = _fnGetOffset = _fnGetClockTime = _fnSetVisualSeason = _fnSetOffset = _fnRevert = 0;
            _fnGetSeason = _fnGetSeasonType = _hookSite = 0;
            _pendingAddr = _doneAddr = _qNaturalAddr = _qEffectiveAddr = _qForcedAddr = 0;
            _desired = null;
            _warnedObject = false;
        }
    }

    public void Dispose() => _holdTimer.Dispose();

    // =====================================================================================
    // Resolution
    // =====================================================================================

    private bool Resolve(out string? error)
    {
        error = null;
        if (_resolved) return true;

        var module = _engine.ReadModuleBytesPublic();
        if (module.Length == 0) { error = "Could not read the game module."; return false; }
        var mb = _engine.MainBase;

        if (!FindUnique(module, SigForceBinding, out var force, out error, "ForceVisualSeason binding")) return false;
        if (!FindUnique(module, SigRevertBinding, out var revert, out error, "RevertVisualSeason binding")) return false;
        if (!FindUnique(module, SigGetSeason, out var getSeason, out error, "GetSeason")) return false;
        if (!FindUnique(module, SigGetSeasonType, out var getSeasonType, out error, "GetCurrentSeasonType")) return false;
        if (!FindUnique(module, SigRollover, out var rollover, out _, "season tick (FinalizeNaturalRollover)"))
        {
            // Our own 5-byte JMP from another instance (or one that died) would hide the prologue.
            if (FindUnique(module, SigRolloverHooked, out var hooked, out _, "season tick (hooked)") && module[hooked] == 0xE9)
                error = "Season: the season tick is already hooked — another trainer instance is running, or a previous one was " +
                        "closed without cleanup. Close other instances; if none is running, restart the game.";
            else
                error = "Season: season tick (FinalizeNaturalRollover) signature not found in this game build — the season cheat needs an update for this version.";
            _engine.LogPublic(error);
            return false;
        }

        ulong RipTarget(int dispOffset) => (ulong)((long)mb + dispOffset + 4 + BitConverter.ToInt32(module, dispOffset));

        // mov rcx,[rip+disp32] is 7 bytes with the disp at +3; call rel32 is 5 bytes with the rel at +1.
        var mgrA = RipTarget(force + ForceMgrMov + 3);
        var fnHasForced = RipTarget(force + ForceCallHasForced + 1);
        var fnGetOffset = RipTarget(force + ForceCallGetOffset + 1);
        var fnGetClock = RipTarget(force + ForceCallGetClock + 1);
        var fnSetVisual = RipTarget(force + ForceCallSetVisual + 1);
        var mgrB = RipTarget(revert + RevertMgrMov + 3);
        var fnSetOffset = RipTarget(revert + RevertCallSetOffset + 1);
        var fnRevert = RipTarget(revert + RevertCallRevert + 1);
        var fnGetSeason = mb + (ulong)getSeason;
        var fnGetSeasonType = mb + (ulong)getSeasonType;

        if (mgrA != mgrB)
        {
            error = $"Season: the two script bindings disagree on the manager global (0x{mgrA:X} vs 0x{mgrB:X}) — refusing.";
            _engine.LogPublic(error);
            return false;
        }
        if (!_engine.IsInModule(mgrA))
        {
            error = $"Season: manager global 0x{mgrA:X} is outside the module — refusing.";
            _engine.LogPublic(error);
            return false;
        }
        foreach (var (fn, name) in new[] { (fnHasForced, "HasForcedVisualSeason"), (fnGetOffset, "GetClockOffset"), (fnGetClock, "GetClockTime"),
                                           (fnSetVisual, "SetVisualSeason"), (fnSetOffset, "SetClockOffset"), (fnRevert, "RevertVisualSeason"),
                                           (fnGetSeason, "GetSeason"), (fnGetSeasonType, "GetCurrentSeasonType") })
        {
            // Every call target must be a function entry: either .pdata says so, or it is a
            // tiny leaf without unwind info (HasForcedVisualSeason) sitting right after padding.
            var ok = _engine.IsInModule(fn);
            if (ok)
            {
                var start = _engine.FindFunctionStart(fn);
                if (start != fn)
                {
                    var prev = module[(int)(fn - mb) - 1];
                    ok = start == 0 && (prev == 0xCC || prev == 0xC3);
                }
            }
            if (!ok)
            {
                error = $"Season: {name} resolved to 0x{fn:X}, which is not a function entry in this build — refusing.";
                _engine.LogPublic(error);
                return false;
            }
        }

        // HasForcedVisualSeason must be `movzx eax, byte [rcx+disp32] ; ret` — that disp is the plain
        // "override active" flag we may read directly for the Hold feature.
        var hf = (int)(fnHasForced - mb);
        if (module[hf] != 0x0F || module[hf + 1] != 0xB6 || module[hf + 2] != 0x81 || module[hf + 7] != 0xC3)
        {
            error = "Season: HasForcedVisualSeason has an unexpected body — refusing.";
            _engine.LogPublic(error);
            return false;
        }
        var offForcedFlag = BitConverter.ToInt32(module, hf + 3);
        if (offForcedFlag is < 0x100 or > 0x2000)
        {
            error = $"Season: forced-flag offset 0x{offForcedFlag:X} out of range — refusing.";
            _engine.LogPublic(error);
            return false;
        }

        // Hook site must be a real function entry that logs its own name.
        var hookSite = mb + (ulong)rollover;
        if (_engine.FindFunctionStart(hookSite) != hookSite)
        {
            error = "Season: tick signature matched mid-function — refusing.";
            _engine.LogPublic(error);
            return false;
        }
        var strOff = IndexOf(module, Encoding.ASCII.GetBytes(RolloverLogString + "\0"));
        if (strOff < 0) { error = "Season: tick log string not found — refusing."; _engine.LogPublic(error); return false; }
        var strAddr = mb + (ulong)strOff;
        var refFound = false;
        for (var i = rollover; i < rollover + 0x800 && i + 7 <= module.Length; i++)
        {
            if (module[i] != 0x4C || module[i + 1] != 0x8D || module[i + 2] != 0x05) continue;       // lea r8,[rip+disp32]
            if (RipTarget(i + 3) == strAddr) { refFound = true; break; }
        }
        if (!refFound)
        {
            error = "Season: tick function does not reference its log string — refusing.";
            _engine.LogPublic(error);
            return false;
        }
        for (var i = 0; i < HookSize; i++)
            if (module[rollover + i] != HookExpected[i])
            {
                error = "Season: tick prologue bytes differ from the expected ones — refusing.";
                _engine.LogPublic(error);
                return false;
            }

        _mgrGlobal = mgrA; _fnHasForced = fnHasForced; _fnGetOffset = fnGetOffset; _fnGetClockTime = fnGetClock;
        _fnSetVisualSeason = fnSetVisual; _fnSetOffset = fnSetOffset; _fnRevert = fnRevert; _hookSite = hookSite;
        _fnGetSeason = fnGetSeason; _fnGetSeasonType = fnGetSeasonType; _offForcedFlag = offForcedFlag;
        _resolved = true;
        _engine.LogPublic($"Season: resolved mgr@0x{mgrA:X} SetVisualSeason=0x{fnSetVisual:X} GetClockTime=0x{fnGetClock:X} " +
                          $"Revert=0x{fnRevert:X} HasForced=0x{fnHasForced:X} (flag +0x{offForcedFlag:X}) GetSeason=0x{fnGetSeason:X} " +
                          $"GetSeasonType=0x{fnGetSeasonType:X} tick=0x{hookSite:X} (+0x{rollover:X})");
        return true;
    }

    private bool FindUnique(byte[] module, string sig, out int offset, out string? error, string what)
    {
        error = null; offset = -1;
        var pat = Pattern.Parse(sig);
        var count = 0;
        foreach (var off in Pattern.FindAll(module, pat, 4))
        {
            count++;
            if (offset < 0) offset = off;
        }
        if (count == 1) return true;
        error = count == 0
            ? $"Season: {what} signature not found in this game build — the season cheat needs an update for this version."
            : $"Season: {what} signature matched {count} sites — refusing to guess.";
        _engine.LogPublic(error);
        return false;
    }

    private static int IndexOf(byte[] hay, byte[] needle) => new ReadOnlySpan<byte>(hay).IndexOf(needle);

    // =====================================================================================
    // Hook + cave
    // =====================================================================================

    /// <summary>Installs the transient tick hook, runs <paramref name="body"/>, removes the hook.</summary>
    private T WithHook<T>(Func<T> body, out string? error)
    {
        error = null;
        try
        {
            _engine.InstallCustomDetour(DetourName, _hookSite, HookSize, 0x200, BuildCave);
        }
        catch (Exception ex)
        {
            error = $"Season hook install failed: {ex.Message}";
            _engine.LogPublic(error);
            return default!;
        }
        try { return body(); }
        finally { _engine.RemoveDetour(DetourName); }
    }

    private byte[] BuildCave(ulong caveAddr)
    {
        var code = BuildCaveBytes(caveAddr, _mgrGlobal, _fnHasForced, _fnGetOffset, _fnGetClockTime, _fnSetVisualSeason,
                                  _fnSetOffset, _fnRevert, _fnGetSeason, _fnGetSeasonType, _hookSite,
                                  out _pendingAddr, out _doneAddr, out _qNaturalAddr, out _qEffectiveAddr, out _qForcedAddr);
        return code;
    }

    /// <summary>
    /// Pure cave emitter (no process access) so the generated code can be unit-checked.
    /// Executed at the entry of the per-frame season tick (rcx = manager, rsp ≡ 8 mod 16):
    ///   if (pending != -1) {
    ///     if (pending == 100) query getters into q_* slots
    ///     else if (pending &lt; 4) force(pending) else revert();
    ///     pending = -1; done++;
    ///   }
    ///   original prologue ; jmp back
    /// </summary>
    internal static byte[] BuildCaveBytes(ulong caveAddr, ulong mgrGlobal, ulong fnHasForced, ulong fnGetOffset, ulong fnGetClockTime,
                                          ulong fnSetVisualSeason, ulong fnSetOffset, ulong fnRevert, ulong fnGetSeason, ulong fnGetSeasonType,
                                          ulong hookSite, out ulong pendingAddr, out ulong doneAddr,
                                          out ulong qNaturalAddr, out ulong qEffectiveAddr, out ulong qForcedAddr)
    {
        var b = new CaveBuilder(caveAddr);
        b.MovEaxFromRip("pending");                 // mov eax,[pending]
        b.Emit(0x83, 0xF8, 0xFF);                   // cmp eax,-1
        b.JccRel32(0x84, "orig");                   // je orig  (hot path: nothing queued)
        b.Emit(0x48, 0x83, 0xEC, 0x38);             // sub rsp,0x38  -> 16-byte aligned for calls, [rsp+0x28] = int64 temp
        b.Emit(0x83, 0xF8, 0x64);                   // cmp eax,100
        b.JccRel32(0x85, "notquery");               // jne notquery

        // ---- query: read the three values through the game's own getters ----
        b.LoadRcxFromAbs(mgrGlobal);
        b.CallAbs(fnGetSeasonType);                 // eax = GetCurrentSeasonType(mgr)  (4 = not loaded)
        b.MovRipFromEax("q_natural");
        b.LoadRcxFromAbs(mgrGlobal);
        b.Emit(0xBA, 0x01, 0x00, 0x00, 0x00);       // mov edx,1 (visual)
        b.CallAbs(fnGetSeason);                     // eax = GetSeason(mgr, true)
        b.MovRipFromEax("q_effective");
        b.LoadRcxFromAbs(mgrGlobal);
        b.CallAbs(fnHasForced);                     // al = HasForcedVisualSeason(mgr)
        b.Emit(0x0F, 0xB6, 0xC0);                   // movzx eax,al
        b.MovRipFromEax("q_forced");
        b.JmpRel32("finish");

        b.Label("notquery");
        b.Emit(0x83, 0xF8, 0x04);                   // cmp eax,4
        b.JccRel32(0x83, "revert");                 // jae revert

        // ---- force path: mirrors the game's ForceVisualSeason script binding ----
        b.LoadRcxFromAbs(mgrGlobal);
        b.CallAbs(fnHasForced);                     // al = HasForcedVisualSeason(mgr)
        b.Emit(0x84, 0xC0);                         // test al,al
        b.JccRel32(0x85, "skipsave");               // jne skipsave  (already forced: keep the saved offset)
        b.LoadRcxFromAbs(mgrGlobal);
        b.Emit(0x48, 0x8D, 0x54, 0x24, 0x28);       // lea rdx,[rsp+0x28]
        b.CallAbs(fnGetOffset);                     // rax -> int64 clock offset
        b.Emit(0x48, 0x8B, 0x00);                   // mov rax,[rax]
        b.MovRipFromRax("saved");                   // saved = offset
        b.Label("skipsave");
        b.LoadRcxFromAbs(mgrGlobal);
        b.Emit(0x48, 0x8D, 0x54, 0x24, 0x28);       // lea rdx,[rsp+0x28]
        b.CallAbs(fnGetClockTime);                  // rax -> int64 now
        b.Emit(0x4C, 0x8B, 0xC0);                   // mov r8,rax
        b.MovEdxFromRip("pending");                 // edx = season
        b.LoadRcxFromAbs(mgrGlobal);
        b.CallAbs(fnSetVisualSeason);               // SetVisualSeason(mgr, season, &now)
        b.JmpRel32("finish");

        // ---- revert path: mirrors the RevertVisualSeason script binding ----
        b.Label("revert");
        b.LoadRcxFromAbs(mgrGlobal);
        b.MovRdxFromRip("saved");                   // rdx = saved offset
        b.CallAbs(fnSetOffset);                     // SetClockOffset(mgr, saved)
        b.LoadRcxFromAbs(mgrGlobal);
        b.Emit(0x31, 0xD2);                         // xor edx,edx
        b.CallAbs(fnRevert);                        // RevertVisualSeason(mgr, false)
        b.MovRipQwordImm32("saved", 0);

        b.Label("finish");
        b.Emit(0x48, 0x83, 0xC4, 0x38);             // add rsp,0x38
        b.MovRipDword("pending", -1);               // pending = -1
        b.IncRipDword("done");                      // done++
        b.LoadRcxFromAbs(mgrGlobal);                // rcx = manager again for the original function

        b.Label("orig");
        b.Emit(HookExpected);                       // mov [rsp+0x20],rbx (the 5 bytes we replaced)
        b.JmpAbs(hookSite + HookSize);

        b.DataInt32("pending", -1);
        b.DataInt32("done", 0);
        b.DataInt32("q_natural", -1);
        b.DataInt32("q_effective", -1);
        b.DataInt32("q_forced", -1);
        b.Data("saved", 8);

        var code = b.Finish();
        pendingAddr = b.AddressOf("pending");
        doneAddr = b.AddressOf("done");
        qNaturalAddr = b.AddressOf("q_natural");
        qEffectiveAddr = b.AddressOf("q_effective");
        qForcedAddr = b.AddressOf("q_forced");
        return code;
    }

    private bool RunOnGameThread(int request, int timeoutMs, out string? error)
    {
        error = null;
        var doneBefore = _engine.ReadInt32Public(_doneAddr);
        _engine.WriteInt32Public(_pendingAddr, request);
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (_engine.ReadInt32Public(_pendingAddr) == -1 && _engine.ReadInt32Public(_doneAddr) != doneBefore) return true;
            Thread.Sleep(15);
        }
        // Not consumed: take the request back so it cannot fire at a random later moment.
        _engine.WriteInt32Public(_pendingAddr, -1);
        error = "The game did not run its season tick in time (paused, in a menu, or still loading?). Try again while driving.";
        _engine.LogPublic($"Season: request {request} timed out — tick hook not executed");
        return false;
    }

    // =====================================================================================
    // State
    // =====================================================================================

    /// <summary>Manager pointer (validated: heap-range pointer whose vtable lies in the module), or 0.</summary>
    private ulong ReadManager()
    {
        var mgr = _engine.ReadUInt64Public(_mgrGlobal);
        if (mgr < 0x10000 || mgr > 0x0000_7FFF_FFFF_FFFF) return 0;
        var vtable = _engine.ReadUInt64Public(mgr);
        if (!_engine.IsInModule(vtable))
        {
            if (!_warnedObject) { _warnedObject = true; _engine.LogPublic($"Season: manager 0x{mgr:X} has a vtable outside the module (0x{vtable:X}) — refusing to use it."); }
            return 0;
        }
        return mgr;
    }

    /// <summary>Runs the query command on the game thread; requires the hook to be installed.</summary>
    private Status? Query(out string? error)
    {
        if (!RunOnGameThread(CmdQuery, 1500, out error)) return null;
        var natural = _engine.ReadInt32Public(_qNaturalAddr);
        var effective = _engine.ReadInt32Public(_qEffectiveAddr);
        var forced = _engine.ReadInt32Public(_qForcedAddr);
        var mgr = ReadManager();
        var state = mgr == 0 ? -1 : _engine.ReadInt32Public(mgr + OffState);
        if (natural is < 0 or > 4 || effective is < 0 or > 5 || forced is < 0 or > 1)
        {
            error = $"Season: getters returned unexpected values (natural={natural}, effective={effective}, forced={forced}) — layout mismatch on this build.";
            _engine.LogPublic(error);
            return null;
        }
        if (state is < 0 or > 32) state = -1;
        return new Status(natural, effective, forced == 1, state);
    }

    private static string Describe(Status s) =>
        $"natural={SeasonName(s.NaturalSeason)} effective={SeasonName(s.EffectiveSeason)} forced={(s.Forced ? "yes" : "no")} state={s.State}";

    // =====================================================================================
    // Hold: re-apply after track swaps / fast travel (cheap plain reads, hook only when needed)
    // =====================================================================================

    private void HoldTick(object? _)
    {
        if (!_hold || _desired is not { } want) return;
        if (Interlocked.Exchange(ref _holdBusy, 1) == 1) return;
        try
        {
            if (!_engine.IsAttached || !_resolved) return;
            if ((DateTime.UtcNow - _lastApplyUtc).TotalSeconds < 8) return;
            bool forced; int state;
            lock (_lock)
            {
                var mgr = ReadManager();
                if (mgr == 0) return;
                var fb = _engine.ReadBytesPublic(mgr + (ulong)_offForcedFlag, 1);
                if (fb.Length != 1 || fb[0] > 1) return;
                forced = fb[0] == 1;
                state = _engine.ReadInt32Public(mgr + OffState);
            }
            if (forced || state is 5 or 6 or 7) return;
            _engine.LogPublic($"Season hold: forced season dropped by the game (state {state}) — re-applying {SeasonName(want)}");
            if (!Apply(want, out var err) && err is not null) _engine.LogPublic($"Season hold: {err}");
        }
        catch (Exception ex) { _engine.LogPublic($"Season hold: {ex.Message}"); }
        finally { Interlocked.Exchange(ref _holdBusy, 0); }
    }
}
