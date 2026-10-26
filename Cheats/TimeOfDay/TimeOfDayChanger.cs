using System;
using System.Threading;
using FH6Mod.Cheats.RuntimeHook;

namespace FH6Mod.Cheats.TimeOfDay;

/// <summary>
/// Holds the in-game clock at a fixed time WITHOUT patching any code.
///
/// Reverse-engineered on v6.440.853.0 (memory dump): the world's TimeOfDay object keeps the
/// current time as seconds-of-day (float, 0..86400) at +0x64, the clock speed at +0x6C, a
/// "stopped" byte at +0x78 (TimeOfDay::Update skips the per-frame advance while it is set)
/// and a "locked" byte at +0x7A (SetTime, ApplyPreset, LoadState and Update's time-source
/// provider all refuse to write the time while it is set). So the whole cheat is three
/// data writes: time, stopped=1, locked=1 — re-asserted a few times per second and undone
/// on disable. No hook means nothing for the integrity check to find and nothing that can
/// be left behind if the trainer dies.
///
/// The object is reached the same way the game's own debug "timeofday" command reaches it:
/// [global] -> +0x1D0 -> +0x128 -> +0x388. The global and the three link offsets are read
/// from that command handler and its two accessor functions at runtime, so a layout change
/// on a new build is detected instead of guessed.
/// </summary>
public sealed class TimeOfDayChanger : IDisposable
{
    // TimeOfDay object fields (v440.853; range-validated before use)
    private const int OffTime = 0x64, OffSpeed = 0x6C, OffStopped = 0x78, OffLocked = 0x7A;

    // Debug command handler: test al,al ; jne ; xor edx,edx ; mov rcx,[world-root global] ;
    // call GetWorld ; mov rcx,rax ; call GetTimeOfDay ; mov rcx,rax ; call SyncToRealTime
    private const string SigChain = "84 C0 0F 85 ? ? ? ? 33 D2 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 8B C8 E8 ? ? ? ?";
    private const int ChainGlobalDisp = 13, ChainCallGetWorld = 18, ChainCallGetTod = 26;

    private readonly RuntimeHookEngine _engine;
    private readonly object _lock = new();
    private readonly Timer _timer;
    private int _busy;

    private bool _resolved;
    private ulong _global;
    private int _off1, _off2, _off3;

    private bool _enabled;
    private float _heldSeconds;
    private ulong _lastObject;
    private byte _savedStopped = 0xFF, _savedLocked = 0xFF;
    private bool _warned;

    public TimeOfDayChanger(RuntimeHookEngine engine)
    {
        _engine = engine;
        _timer = new Timer(Tick, null, 250, 250);
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
            if (!_enabled)
            {
                _savedStopped = ReadByte(tod + OffStopped);
                _savedLocked = ReadByte(tod + OffLocked);
            }
            _enabled = true;
            Assert(tod);
            _engine.LogPublic($"TimeOfDay: holding {Hours(_heldSeconds)} (object 0x{tod:X}, was stopped={_savedStopped} locked={_savedLocked})");
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
            Assert(tod);
            _engine.LogPublic($"TimeOfDay: now holding {Hours(_heldSeconds)}");
            return true;
        }
    }

    /// <summary>Lets the clock run again, restoring the game's own stopped/locked flags.</summary>
    public bool Disable(out string? error)
    {
        error = null;
        lock (_lock)
        {
            if (!_enabled) return true;
            _enabled = false;
            if (!_engine.IsAttached) return true;
            var tod = FindObject(out _);
            if (tod != 0 && _savedStopped != 0xFF)
            {
                try
                {
                    _engine.WriteBytesPublic(tod + OffStopped, [_savedStopped]);
                    _engine.WriteBytesPublic(tod + OffLocked, [_savedLocked]);
                    _engine.LogPublic($"TimeOfDay: released (stopped={_savedStopped} locked={_savedLocked} restored)");
                }
                catch (Exception ex) { error = ex.Message; }
            }
            _savedStopped = _savedLocked = 0xFF;
            return error is null;
        }
    }

    public void Reset()
    {
        lock (_lock)
        {
            _resolved = false; _global = 0; _off1 = _off2 = _off3 = 0;
            _enabled = false; _lastObject = 0; _savedStopped = _savedLocked = 0xFF; _warned = false;
        }
    }

    public void Dispose() => _timer.Dispose();

    // ------------------------------------------------------------------------------------

    private bool Resolve(out string? error)
    {
        error = null;
        if (_resolved) return true;
        var module = _engine.ReadModuleBytesPublic();
        if (module.Length == 0) { error = "Could not read the game module."; return false; }
        var mb = _engine.MainBase;

        var pat = Pattern.Parse(SigChain);
        int match = -1, count = 0;
        foreach (var off in Pattern.FindAll(module, pat, 4)) { count++; if (match < 0) match = off; }
        if (count != 1)
        {
            error = count == 0 ? "Time of Day: clock accessor chain not found in this game build — needs an update for this version."
                               : $"Time of Day: clock accessor chain matched {count} sites — refusing to guess.";
            _engine.LogPublic(error);
            return false;
        }

        ulong Rip(int dispOff) => (ulong)((long)mb + dispOff + 4 + BitConverter.ToInt32(module, dispOff));
        var global = Rip(match + ChainGlobalDisp);
        var fnWorld = Rip(match + ChainCallGetWorld);
        var fnTod = Rip(match + ChainCallGetTod);
        if (!_engine.IsInModule(global) || !_engine.IsInModule(fnWorld) || !_engine.IsInModule(fnTod))
        {
            error = "Time of Day: accessor chain points outside the module — refusing."; _engine.LogPublic(error); return false;
        }

        // GetWorld: mov rcx,[rcx+off1] ; test rcx,rcx ; jne <fn2> ; xor eax,eax ; ret   with fn2: mov rax,[rcx+off2] ; ret
        var w = (int)(fnWorld - mb);
        if (!(module[w] == 0x48 && module[w + 1] == 0x8B && module[w + 2] == 0x89 && module[w + 7] == 0x48 && module[w + 8] == 0x85 && module[w + 9] == 0xC9
              && module[w + 10] == 0x0F && module[w + 11] == 0x85))
        {
            error = "Time of Day: GetWorld has an unexpected shape — refusing."; _engine.LogPublic(error); return false;
        }
        var off1 = BitConverter.ToInt32(module, w + 3);
        var fn2 = Rip(w + 12);
        var f2 = (int)(fn2 - mb);
        if (!_engine.IsInModule(fn2) || !(module[f2] == 0x48 && module[f2 + 1] == 0x8B && module[f2 + 2] == 0x81 && module[f2 + 7] == 0xC3))
        {
            error = "Time of Day: world accessor has an unexpected shape — refusing."; _engine.LogPublic(error); return false;
        }
        var off2 = BitConverter.ToInt32(module, f2 + 3);
        // GetTimeOfDay: mov rax,[rcx+off3] ; ret
        var t = (int)(fnTod - mb);
        if (!(module[t] == 0x48 && module[t + 1] == 0x8B && module[t + 2] == 0x81 && module[t + 7] == 0xC3))
        {
            error = "Time of Day: GetTimeOfDay has an unexpected shape — refusing."; _engine.LogPublic(error); return false;
        }
        var off3 = BitConverter.ToInt32(module, t + 3);
        if (off1 is <= 0 or > 0x4000 || off2 is <= 0 or > 0x4000 || off3 is <= 0 or > 0x4000)
        {
            error = "Time of Day: accessor offsets out of range — refusing."; _engine.LogPublic(error); return false;
        }

        _global = global; _off1 = off1; _off2 = off2; _off3 = off3; _resolved = true;
        _engine.LogPublic($"TimeOfDay: resolved chain [0x{global:X}] -> +0x{off1:X} -> +0x{off2:X} -> +0x{off3:X}");
        return true;
    }

    /// <summary>Walks the pointer chain and validates the object; 0 (with error) when not available.</summary>
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
        if (tod != _lastObject)
        {
            if (_lastObject != 0 && _enabled)
            {
                // World was re-created (track swap): the saved flags belong to the old object.
                _savedStopped = stopped; _savedLocked = locked;
            }
            _lastObject = tod;
        }
        return tod;
    }

    private void Assert(ulong tod)
    {
        _engine.WriteBytesPublic(tod + OffStopped, [1]);
        _engine.WriteBytesPublic(tod + OffLocked, [1]);
        _engine.WriteBytesPublic(tod + OffTime, BitConverter.GetBytes(_heldSeconds));
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
                var cur = ReadFloat(tod + OffTime);
                if (ReadByte(tod + OffStopped) != 1 || ReadByte(tod + OffLocked) != 1 || Math.Abs(cur - _heldSeconds) > 2f)
                    Assert(tod);
            }
        }
        catch (Exception ex) { if (!_warned) { _warned = true; _engine.LogPublic($"TimeOfDay: {ex.Message}"); } }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }

    private static bool IsPtr(ulong v) => v >= 0x10000 && v <= 0x0000_7FFF_FFFF_FFFF;
    private static float Clamp(float s) => float.IsNaN(s) ? 43200f : Math.Max(0f, Math.Min(86399f, s));
    private static string Hours(float s) => $"{(int)(s / 3600):00}:{(int)(s % 3600 / 60):00}";
    private byte ReadByte(ulong a) { var b = _engine.ReadBytesPublic(a, 1); return b.Length == 1 ? b[0] : (byte)0xFF; }
    private float ReadFloat(ulong a) { var b = _engine.ReadBytesPublic(a, 4); return b.Length == 4 ? BitConverter.ToSingle(b, 0) : float.NaN; }
}
