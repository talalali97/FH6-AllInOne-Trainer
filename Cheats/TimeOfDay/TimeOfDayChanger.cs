using System;
using System.Threading;
using FH6Mod.Cheats.RuntimeHook;

namespace FH6Mod.Cheats.TimeOfDay;

/// <summary>
/// Holds the in-game clock at a fixed time with data writes only (no code patch).
///
/// How the clock really works on v6.440.853.0 (decrypted dump + live trace + adversarially
/// verified static analysis):
///   * The world's TimeOfDay object T keeps the time as seconds-of-day (float 0..86400) at +0x64.
///     Every frame ForzaSimulation::UpdateWeatherAndTimeOfDayManagers runs TimeOfDay::Update
///     (which copies +0x64 into the lighting/sky packet) and THEN the weather manager WM.
///   * In free roam WM plays a weather script (the forecast timeline). Its player TL
///     interpolates a keyframe track driven by the real calendar and writes the result into
///     T+0x64 every frame (helper "mov eax,[rdx+4]; mov [rcx+0x64],eax"), ignoring T's
///     "stopped"/"locked" flags. Any value written into T from outside is replaced one frame
///     later — which is exactly the flicker earlier versions produced. (Re-pointing the
///     player's clock pointer does not help: the world re-points it at T every frame.)
///   * The game has its own pause for that timeline, used by its console/script time commands
///     right before they apply a time: if byte [WM+allow] != 0 then byte [TL+0] = 1. While
///     paused the timeline stops writing T, TimeOfDay::Update keeps its own advance off, and
///     nothing else writes T+0x64 per frame — so a single write holds. The weather schedule
///     is frozen with it.
///   * Safety: when [WM+allow] == 0 the game never pauses, and a paused timeline in that state
///     makes the weather manager tear the script down permanently. So we refuse in that case.
///   * Release: restore the pause byte; the next frame re-derives the time from the calendar.
///   * If the trainer dies while holding, the timeline just stays paused (the game's normal
///     paused state) until the game resumes it itself, e.g. on the next world load.
///
/// T is reached the way the game's debug "timeofday" command does: [global] -> +0x1D0 ->
/// +0x128 -> +0x388. The weather-manager global and its offsets are parsed from the game's
/// own code at runtime and cross-checked between two functions.
/// </summary>
public sealed class TimeOfDayChanger : IDisposable
{
    // TimeOfDay object fields (v440.853; range-validated before use)
    private const int OffPrevTime = 0x60, OffTime = 0x64, OffSpeed = 0x6C, OffStopped = 0x78, OffLocked = 0x7A,
                      OffSpeedFlag = 0x7B, OffTransition = 0x7D;
    private const int OffTimelineKeys = 0x28;   // TL+0x28: keyframe stream (0 = no script loaded)

    // Debug command handler: test al,al ; jne ; xor edx,edx ; mov rcx,[world-root global] ;
    // call GetWorld ; mov rcx,rax ; call GetTimeOfDay ; mov rcx,rax ; call SyncToRealTime
    private const string SigChain = "84 C0 0F 85 ? ? ? ? 33 D2 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 8B C8 E8 ? ? ? ?";
    private const int ChainGlobalDisp = 13, ChainCallGetWorld = 18, ChainCallGetTod = 26;

    // "Weather script drives time" check: push rbx ; sub rsp,20 ; mov rbx,[WM global] ; ... ;
    // cmp dword [rbx+modeOff],1 ; jne ; cmp qword [rbx+playerOff],0 ; je
    private const string SigScriptMode = "40 53 48 83 EC 20 48 8B 1D ? ? ? ? 48 85 DB 74 ? 48 8B CB E8 ? ? ? ? 84 C0 75 ? 83 BB ? ? ? ? 01 75 ? 48 83 BB ? ? ? ? 00 74";
    private const int ModeGlobalDisp = 9, ModeModeOff = 0x20, ModePlayerOff = 0x2A;

    // The game's own timeline pause: cmp byte [rcx+allowOff],0 ; je ; mov rax,[rcx+playerOff] ; mov byte [rax],1 ; ret
    private const string SigPause = "80 B9 ? ? ? ? 00 74 0A 48 8B 81 ? ? ? ? C6 00 01 C3";
    private const int PauseAllowOff = 2, PausePlayerOff = 12;

    private readonly RuntimeHookEngine _engine;
    private readonly object _lock = new();
    private readonly Timer _timer;
    private int _busy;

    private bool _resolved;
    private ulong _global;
    private int _off1, _off2, _off3;
    private ulong _wmGlobal;
    private int _offMode, _offPlayer, _offAllow;

    private bool _enabled;
    private float _heldSeconds;
    private ulong _pausedPlayer;     // TL we paused (0 = none)
    private byte _savedPause = 0xFF;
    private ulong _heldObject;       // T we are holding
    private byte _savedStopped = 0xFF;  // only used in the no-timeline fallback
    private bool _warned;
    private DateTime _lastLogUtc = DateTime.MinValue;

    public TimeOfDayChanger(RuntimeHookEngine engine)
    {
        _engine = engine;
        _timer = new Timer(Tick, null, 150, 150);
    }

    public bool Enabled => _enabled;

    /// <summary>Starts holding the clock at <paramref name="seconds"/> of day (0..86400).</summary>
    public bool Enable(float seconds, out string? error)
    {
        error = null;
        lock (_lock)
        {
            if (!_engine.IsAttached) { error = "Not attached."; return false; }
            if (!Resolve(out error)) return false;
            var tod = FindObject(out error);
            if (tod == 0) return false;
            _heldSeconds = Clamp(seconds);
            if (!Hold(tod, out var how, out error)) return false;
            _enabled = true;
            _engine.LogPublic($"TimeOfDay: holding {Hours(_heldSeconds)} (clock 0x{tod:X}, {how})");
            return true;
        }
    }

    /// <summary>Changes the held time while enabled.</summary>
    public bool Update(float seconds, out string? error)
    {
        error = null;
        lock (_lock)
        {
            if (!_enabled) { error = "Time of Day is not enabled."; return false; }
            _heldSeconds = Clamp(seconds);
            var tod = FindObject(out error);
            if (tod == 0) return false;
            if (!Hold(tod, out _, out error)) return false;
            _engine.LogPublic($"TimeOfDay: now holding {Hours(_heldSeconds)}");
            return true;
        }
    }

    /// <summary>Gives the clock back to the game.</summary>
    public bool Disable(out string? error)
    {
        error = null;
        lock (_lock)
        {
            if (!_enabled) return true;
            _enabled = false;
            if (!_engine.IsAttached) return true;
            try
            {
                Release();
                _engine.LogPublic("TimeOfDay: released, clock follows the game's schedule again");
            }
            catch (Exception ex) { error = ex.Message; }
            return error is null;
        }
    }

    public void Reset()
    {
        lock (_lock)
        {
            _resolved = false; _global = _wmGlobal = 0; _off1 = _off2 = _off3 = 0;
            _enabled = false; _pausedPlayer = _heldObject = 0; _savedPause = _savedStopped = 0xFF; _warned = false;
        }
    }

    public void Dispose() => _timer.Dispose();

    // ------------------------------------------------------------------------------------
    // Hold / release

    private bool Hold(ulong tod, out string how, out string? error)
    {
        error = null;
        how = "";
        var wm = _engine.ReadUInt64Public(_wmGlobal);
        var player = FindTimeline(wm);
        if (player != 0)
        {
            var allow = ReadByte(wm + (ulong)_offAllow);
            if (allow != 1)
            {
                // The game itself refuses to pause here, and a paused timeline in this state gets
                // torn down for good — never touch the pause byte.
                error = "Time of Day can't be held right now: the game's weather schedule doesn't allow pausing in this mode. Try again in normal free roam.";
                _engine.LogPublic($"TimeOfDay: refusing — weather manager pause-allowed byte is {allow}");
                return false;
            }
            if (_pausedPlayer != player) { _pausedPlayer = player; _savedPause = ReadByte(player); }
            if (_savedPause > 1) _savedPause = 0;
            _engine.WriteBytesPublic(player, [1]);   // exactly what the game's own pause does
            how = $"weather timeline 0x{player:X} paused";
        }
        else
        {
            // No timeline driving time (e.g. an event owns it): Update's own advance is the only
            // per-frame writer, and "stopped" turns that off.
            if (_heldObject != tod || _savedStopped == 0xFF) _savedStopped = ReadByte(tod + OffStopped);
            _engine.WriteBytesPublic(tod + OffStopped, [1]);
            how = "no weather timeline active, clock stopped directly";
        }
        _heldObject = tod;
        var bits = BitConverter.GetBytes(_heldSeconds);
        _engine.WriteBytesPublic(tod + OffTransition, [0]);
        _engine.WriteBytesPublic(tod + OffSpeedFlag, [0]);
        _engine.WriteBytesPublic(tod + OffTime, bits);
        _engine.WriteBytesPublic(tod + OffPrevTime, bits);   // no one-off "time jumped" lighting reset
        return true;
    }

    private void Release()
    {
        if (_pausedPlayer != 0)
        {
            var wm = _engine.ReadUInt64Public(_wmGlobal);
            if (FindTimeline(wm) == _pausedPlayer)
                _engine.WriteBytesPublic(_pausedPlayer, [_savedPause == 1 ? (byte)1 : (byte)0]);
        }
        if (_heldObject != 0 && _savedStopped != 0xFF && IsPtr(_heldObject))
            _engine.WriteBytesPublic(_heldObject + OffStopped, [_savedStopped == 1 ? (byte)1 : (byte)0]);
        _pausedPlayer = 0; _savedPause = 0xFF; _heldObject = 0; _savedStopped = 0xFF;
    }

    private void Tick(object? state)
    {
        if (!_enabled || Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            lock (_lock)
            {
                if (!_enabled || !_engine.IsAttached || !_resolved) return;
                var tod = FindObject(out _);
                if (tod == 0) return;
                var wm = _engine.ReadUInt64Public(_wmGlobal);
                var player = FindTimeline(wm);
                var paused = player == 0 || ReadByte(player) == 1;
                var cur = ReadFloat(tod + OffTime);
                if (paused && player == _pausedPlayer && tod == _heldObject && Math.Abs(cur - _heldSeconds) < 0.01f) return;
                // The game resumed the timeline, reloaded the world, or something else set the time.
                if ((DateTime.UtcNow - _lastLogUtc).TotalSeconds >= 5)
                {
                    _engine.LogPublic($"TimeOfDay: re-applying hold (time={cur:0.0}, paused={paused}, sameTimeline={player == _pausedPlayer}, sameClock={tod == _heldObject})");
                    _lastLogUtc = DateTime.UtcNow;
                }
                if (player != _pausedPlayer) { _pausedPlayer = 0; _savedPause = 0xFF; }
                Hold(tod, out _, out _);
            }
        }
        catch (Exception ex) { if (!_warned) { _warned = true; _engine.LogPublic($"TimeOfDay: {ex.Message}"); } }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }

    // ------------------------------------------------------------------------------------
    // Resolution

    private bool Resolve(out string? error)
    {
        error = null;
        if (_resolved) return true;
        var module = _engine.ReadModuleBytesPublic();
        if (module.Length == 0) { error = "Could not read the game module."; return false; }
        var mb = _engine.MainBase;
        ulong Rip(int dispOff) => (ulong)((long)mb + dispOff + 4 + BitConverter.ToInt32(module, dispOff));

        int Unique(string sig, string what)
        {
            var pat = Pattern.Parse(sig);
            int m = -1, c = 0;
            foreach (var off in Pattern.FindAll(module, pat, 4)) { c++; if (m < 0) m = off; }
            if (c == 1) return m;
            _engine.LogPublic(c == 0 ? $"Time of Day: {what} not found in this game build." : $"Time of Day: {what} matched {c} sites — refusing to guess.");
            return -1;
        }

        // --- the clock object chain
        var chain = Unique(SigChain, "clock accessor chain");
        if (chain < 0) { error = "Time of Day: clock accessor chain not found in this game build — needs an update for this version."; return false; }
        var global = Rip(chain + ChainGlobalDisp);
        var fnWorld = Rip(chain + ChainCallGetWorld);
        var fnTod = Rip(chain + ChainCallGetTod);
        if (!_engine.IsInModule(global) || !_engine.IsInModule(fnWorld) || !_engine.IsInModule(fnTod))
        { error = "Time of Day: accessor chain points outside the module — refusing."; _engine.LogPublic(error); return false; }
        var w = (int)(fnWorld - mb);
        if (!(module[w] == 0x48 && module[w + 1] == 0x8B && module[w + 2] == 0x89 && module[w + 7] == 0x48 && module[w + 8] == 0x85 && module[w + 9] == 0xC9
              && module[w + 10] == 0x0F && module[w + 11] == 0x85))
        { error = "Time of Day: GetWorld has an unexpected shape — refusing."; _engine.LogPublic(error); return false; }
        var off1 = BitConverter.ToInt32(module, w + 3);
        var fn2 = Rip(w + 12);
        var f2 = (int)(fn2 - mb);
        if (!_engine.IsInModule(fn2) || !(module[f2] == 0x48 && module[f2 + 1] == 0x8B && module[f2 + 2] == 0x81 && module[f2 + 7] == 0xC3))
        { error = "Time of Day: world accessor has an unexpected shape — refusing."; _engine.LogPublic(error); return false; }
        var off2 = BitConverter.ToInt32(module, f2 + 3);
        var t = (int)(fnTod - mb);
        if (!(module[t] == 0x48 && module[t + 1] == 0x8B && module[t + 2] == 0x81 && module[t + 7] == 0xC3))
        { error = "Time of Day: GetTimeOfDay has an unexpected shape — refusing."; _engine.LogPublic(error); return false; }
        var off3 = BitConverter.ToInt32(module, t + 3);
        if (off1 is <= 0 or > 0x4000 || off2 is <= 0 or > 0x4000 || off3 is <= 0 or > 0x4000)
        { error = "Time of Day: accessor offsets out of range — refusing."; _engine.LogPublic(error); return false; }

        // --- the weather timeline that overwrites the clock every frame, and the game's pause for it
        var mode = Unique(SigScriptMode, "weather-timeline mode check");
        var pause = Unique(SigPause, "weather-timeline pause");
        if (mode < 0 || pause < 0)
        { error = "Time of Day: the weather-timeline code was not found in this game build — needs an update for this version."; return false; }
        var wmGlobal = Rip(mode + ModeGlobalDisp);
        var offMode = BitConverter.ToInt32(module, mode + ModeModeOff);
        var offPlayer = BitConverter.ToInt32(module, mode + ModePlayerOff);
        var offPlayer2 = BitConverter.ToInt32(module, pause + PausePlayerOff);
        var offAllow = BitConverter.ToInt32(module, pause + PauseAllowOff);
        if (!_engine.IsInModule(wmGlobal) || offPlayer != offPlayer2 || offMode is <= 0 or > 0x2000 || offPlayer is <= 0 or > 0x2000
            || offAllow is <= 0 or > 0x2000)
        {
            error = $"Time of Day: weather-timeline offsets do not line up (mode 0x{offMode:X}, player 0x{offPlayer:X}/0x{offPlayer2:X}, allow 0x{offAllow:X}) — refusing.";
            _engine.LogPublic(error);
            return false;
        }

        _global = global; _off1 = off1; _off2 = off2; _off3 = off3;
        _wmGlobal = wmGlobal; _offMode = offMode; _offPlayer = offPlayer; _offAllow = offAllow;
        _resolved = true;
        _engine.LogPublic($"TimeOfDay: resolved clock [0x{global:X}] -> +0x{off1:X} -> +0x{off2:X} -> +0x{off3:X}; " +
                          $"weather [0x{wmGlobal:X}] mode +0x{offMode:X}, timeline +0x{offPlayer:X}, pause-allowed +0x{offAllow:X}");
        return true;
    }

    /// <summary>Walks the pointer chain and validates the clock object; 0 (with error) when not available.</summary>
    private ulong FindObject(out string? error)
    {
        error = null;
        var root = _engine.ReadUInt64Public(_global);
        var p = IsPtr(root) ? _engine.ReadUInt64Public(root + (ulong)_off1) : 0;
        var world = IsPtr(p) ? _engine.ReadUInt64Public(p + (ulong)_off2) : 0;
        var tod = IsPtr(world) ? _engine.ReadUInt64Public(world + (ulong)_off3) : 0;
        if (!IsPtr(tod)) { error = "The world is not loaded yet — drive in free roam, then try again."; return 0; }
        var time = ReadFloat(tod + OffTime);
        var speed = ReadFloat(tod + OffSpeed);
        var stopped = ReadByte(tod + OffStopped);
        var locked = ReadByte(tod + OffLocked);
        if (float.IsNaN(time) || time < 0f || time > 86400f || float.IsNaN(speed) || speed < 0f || speed > 100000f || stopped > 1 || locked > 1)
        {
            if (!_warned) { _warned = true; _engine.LogPublic($"TimeOfDay: object 0x{tod:X} fields out of range (time={time}, speed={speed}, stopped={stopped}, locked={locked}) — layout mismatch on this build."); }
            error = "Time of Day: clock object layout does not match this game build.";
            return 0;
        }
        return tod;
    }

    /// <summary>The weather timeline currently driving the clock, or 0 when none is.</summary>
    private ulong FindTimeline(ulong wm)
    {
        if (!IsPtr(wm)) return 0;
        if (_engine.ReadInt32Public(wm + (ulong)_offMode) != 1) return 0;
        var player = _engine.ReadUInt64Public(wm + (ulong)_offPlayer);
        if (!IsPtr(player)) return 0;
        if (!IsPtr(_engine.ReadUInt64Public(player + OffTimelineKeys))) return 0;
        return player;
    }

    private static bool IsPtr(ulong v) => v >= 0x10000 && v <= 0x0000_7FFF_FFFF_FFFF;
    private static float Clamp(float s) => float.IsNaN(s) ? 43200f : Math.Max(0f, Math.Min(86399f, s));
    private static string Hours(float s) => $"{(int)(s / 3600):00}:{(int)(s % 3600 / 60):00}";
    private byte ReadByte(ulong a) { var b = _engine.ReadBytesPublic(a, 1); return b.Length == 1 ? b[0] : (byte)0xFF; }
    private float ReadFloat(ulong a) { var b = _engine.ReadBytesPublic(a, 4); return b.Length == 4 ? BitConverter.ToSingle(b, 0) : float.NaN; }
}
