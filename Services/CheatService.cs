using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using FH6Mod.Cheats.RuntimeHook;
using FH6Mod.Cheats.Season;
using FH6Mod.Cheats.Sql;
using FH6Mod.Cheats.TimeOfDay;
using FH6Mod.Cheats.Weather;
using FH6Mod.Cheats.Xp;

namespace FH6Mod.Services;

public sealed class CheatService : IDisposable
{
    private readonly GameProcessService _game;
    private readonly LogService _log;
    private readonly RuntimeHookEngine _engine = new();
    private readonly SqlExecutor _sql;
    private readonly SeasonChanger _season;
    private readonly TimeOfDayChanger _tod;
    private readonly WeatherChanger _weather;
    private readonly XpCaller _xp;
    private readonly RewardCaller _reward;
    private readonly HashSet<RuntimeProfileFeature> _active = new();
    private int _lastAttachedPid;

    public LogService LogSvc => _log;
    public string? LastError { get; private set; }
    public string Diagnostics => _engine.DiagnosticsTail();

    public bool IsAttached => _engine.IsAttached;
    public bool IsActive(RuntimeProfileFeature f) => _active.Contains(f);

    public CheatService(GameProcessService game, LogService log)
    {
        _game = game;
        _log = log;
        _sql = new SqlExecutor(_engine);
        _season = new SeasonChanger(_engine);
        _tod = new TimeOfDayChanger(_engine);
        _weather = new WeatherChanger(_engine);
        _xp = new XpCaller(_engine);
        _reward = new RewardCaller(_engine);
        _engine.SetLogCallback(msg => _log.Info(msg));
        _game.StatusChanged += OnGameStatusChanged;
    }

    private int _disposed;

    /// <summary>
    /// Restores every hook and the integrity-check pointer in the game, then releases the
    /// process handle. Idempotent — called from the Avalonia Exit event, the main window's
    /// Closing event, AppDomain.ProcessExit and the unhandled-exception handler, because a
    /// hook left behind by a dead trainer gets the game killed by its integrity check.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        _log.Info("Trainer closing — restoring game hooks");
        try { _game.StatusChanged -= OnGameStatusChanged; } catch { }
        try { _tod.Disable(out _); } catch { }
        try { _season.Dispose(); } catch { }
        try { _tod.Dispose(); } catch { }
        try { _engine.Dispose(); } catch (Exception ex) { _log.Error($"Cleanup failed: {ex.Message}"); }
        _log.Info("Trainer cleanup done");
    }

    private void OnGameStatusChanged()
    {
        if (!_game.IsAttached && _engine.IsAttached)
        {
            _log.Info("Game exited while attached — cleaning up hooks");
            _active.Clear();
            _sql.Reset();
            _season.Reset();
            _tod.Reset();
            _weather.Reset();
            try { _engine.Detach(); }
            catch (Exception ex) { LastError = $"Detach on game-exit failed: {ex.Message}"; _log.Error($"Detach failed: {ex.Message}"); }
        }
    }

    public bool RunSql(SqlFeature feature)
    {
        if (!EnsureAttached()) return false;
        var f = SqlFeatureCatalog.Get(feature);
        _log.Info($"SQL: executing {f.Name} ({f.Queries.Length} queries)");
        foreach (var q in f.Queries)
        {
            if (!_sql.Execute(q, out var err))
            {
                LastError = $"{f.Name}: {err}";
                _log.Error($"SQL {f.Name} failed: {err}");
                return false;
            }
        }
        _log.Info($"SQL: {f.Name} OK");
        LastError = null;
        return true;
    }

    public bool EnsureAttached()
    {
        if (!_game.IsAttached)
        {
            LastError = "Forza Horizon 6 is not running.";
            _log.Error("EnsureAttached: FH6 not running");
            return false;
        }
        if (_engine.IsAttached && _lastAttachedPid == _game.Pid) return true;

        // The engine self-cleans stale state from a previous game process inside
        // Attach(); here we only drop our own toggle bookkeeping when the PID changes.
        var previousPid = _lastAttachedPid;

        _log.Info($"Attaching to PID {_game.Pid}...");
        if (!_engine.Attach(_game.Pid!.Value))
        {
            LastError = "OpenProcess failed (need admin? or game still loading?).";
            _log.Error("Attach failed — OpenProcess returned null. Run as admin?");
            return false;
        }
        if (previousPid != _game.Pid)
        {
            // New game process: every cached pointer belongs to the old address space.
            // The game-lost cleanup can be missed when the game dies and relaunches
            // inside one 2s poll, so re-attach must drop all per-process state here —
            // stale SqlExecutor candidate/locks spawned crashing remote threads that
            // the game surfaced as crash-dialog spam (#196).
            _active.Clear();
            _sql.Reset();
            _reward.Reset();
            _season.Reset();
            _tod.Reset();
            _weather.Reset();
        }
        _lastAttachedPid = _game.Pid!.Value;
        _log.Info($"Attached OK — engine ready");

        // Resolve the season system (signature scan only — no hook, no writes) and log it.
        _log.Info($"Season on attach: {_season.DescribeStatus(allowHook: false)}");
        LastError = null;
        return true;
    }

    public bool Apply(RuntimeProfileFeature feature, int value, bool enabled)
    {
        var name = feature.ToString();
        if (!EnsureAttached()) return false;
        _log.Info($"{name}: {(enabled ? "enabling" : "disabling")} @ {value}");
        if (feature == RuntimeProfileFeature.TimeOfDay)
        {
            // Data-driven: value carries the float bits of seconds-of-day.
            var ok = enabled ? _tod.Enable(BitConverter.Int32BitsToSingle(value), out var terr) : _tod.Disable(out terr);
            if (!ok) { LastError = terr; _log.Error($"{name} apply: {terr}"); return false; }
            if (enabled) _active.Add(feature); else _active.Remove(feature);
            _log.Info($"{name}: {(enabled ? "ENABLED" : "DISABLED")} OK");
            LastError = null;
            return true;
        }
        if (!_engine.ApplyProfile(feature, value, enabled, out var err))
        {
            LastError = err;
            _log.Error($"{name} apply: {err}");
            return false;
        }
        if (enabled) _active.Add(feature); else _active.Remove(feature);
        _log.Info($"{name}: {(enabled ? "ENABLED" : "DISABLED")} OK");
        LastError = null;
        return true;
    }

    public bool UpdateValue(RuntimeProfileFeature feature, int value)
    {
        var name = feature.ToString();
        _log.Info($"{name}: updating value to {value}");
        if (!EnsureAttached()) return false;
        if (feature == RuntimeProfileFeature.TimeOfDay)
        {
            if (!_tod.Update(BitConverter.Int32BitsToSingle(value), out var terr)) { LastError = terr; _log.Error($"{name} update: {terr}"); return false; }
            _log.Info($"{name}: value updated OK");
            LastError = null;
            return true;
        }
        if (!_engine.UpdateValue(feature, value, out var err))
        {
            LastError = err;
            _log.Error($"{name} update: {err}");
            return false;
        }
        _log.Info($"{name}: value updated OK");
        LastError = null;
        return true;
    }

    public bool ToggleSqlLock(SqlFeature feature, bool on, int periodSec = 10)
    {
        if (!EnsureAttached()) return false;
        var f = SqlFeatureCatalog.Get(feature);
        var revert = SqlFeatureCatalog.GetRevert(feature);
        _log.Info($"SQL Lock {f.Name}: {(on ? "ON" : "OFF")}");
        var ok = on
            ? _sql.StartLock(feature, f.Queries, periodSec, out var err)
            : _sql.StopLock(feature, revert, out err);
        if (!ok) { LastError = $"{f.Name}: {err}"; _log.Error($"SQL Lock {f.Name}: {err}"); }
        else { LastError = null; _log.Info($"SQL Lock {f.Name}: OK"); }
        return ok;
    }

    public bool IsSqlLockActive(SqlFeature feature) => _sql.IsLockActive(feature);

    // ===== Instant reward grants (Phorza-style: call the game's grant function via shellcode) =====

    private bool GrantReward(int type, int amount, string label)
    {
        if (!EnsureAttached()) return false;
        if (!_reward.SetReward(type, amount, out var err))
        {
            LastError = err ?? $"{label} failed.";
            _log.Error($"{label}: {LastError}");
            return false;
        }
        _log.Info($"Set {label} to {amount} (wallet data-write, type={type})");
        LastError = null;
        return true;
    }

    public bool GrantWheelspins(int amount) => GrantReward(0, amount, "Wheelspins");
    public bool GrantSuperWheelspins(int amount) => GrantReward(1, amount, "Super Wheelspins");

    /// <summary>Current wallet counts, or null when the wallet is not resolved on this build.</summary>
    public (int Wheelspins, int SuperWheelspins)? GetCurrentRewards()
        => _engine.IsAttached ? _reward.GetCurrentRewards() : null;

    /// <summary>
    /// Dumps the decrypted main module next to the trainer. Returns the path, or null
    /// with <paramref name="error"/> set.
    /// </summary>
    public string? DumpGameModule(out string? error)
    {
        error = null;
        if (!EnsureAttached()) { error = LastError ?? "Not attached."; return null; }
        try
        {
            var path = System.IO.Path.Combine(AppContext.BaseDirectory, $"fh6_module_{_game.Pid}.bin");
            _engine.DumpMainModule(path);
            LastError = null;
            return path;
        }
        catch (Exception ex)
        {
            error = $"Dump failed: {ex.Message}";
            _log.Error(error);
            return null;
        }
    }

    public List<(RuntimeProfileFeature Feature, bool Found, string Detail)> ScanAllSignatures()
    {
        if (!EnsureAttached()) return Enum.GetValues<RuntimeProfileFeature>()
            .Select(f => (f, false, "Not attached")).ToList();
        return _engine.ScanAllSignatures();
    }

    /// <summary>
    /// Current season state as the game's SeasonManager reports it, or null. With
    /// <paramref name="allowHook"/> the trainer briefly hooks the season tick to run the
    /// game's getters on the game thread; without it nothing is touched (always null).
    /// </summary>
    public SeasonChanger.Status? GetSeasonStatus(bool allowHook)
        => _engine.IsAttached && EnsureAttached() ? _season.ReadStatusSafe(allowHook) : null;

    /// <summary>Re-apply the chosen season automatically after track swaps / fast travel.</summary>
    public bool SeasonHold
    {
        get => _season.Hold;
        set { _season.Hold = value; _log.Info($"Season hold {(value ? "ON" : "OFF")}"); }
    }

    public int? DesiredSeason => _season.DesiredSeason;

    /// <summary>
    /// Switches the visual season (0-3). The hook is strictly opt-in: installed here, only
    /// when the user invokes a Season feature — never as a side effect of other cheats.
    /// </summary>
    public bool SetSeason(int season, out string? error)
    {
        error = null;
        if (!EnsureAttached()) { error = "Not attached."; return false; }
        if (season < 0 || season > 3) { error = "Invalid season (0-3)."; return false; }
        if (!_season.Apply(season, out var err))
        {
            error = err ?? "Season switch failed.";
            _log.Error(error);
            return false;
        }
        LastError = null;
        return true;
    }

    /// <summary>Drops the forced season and lets the schedule decide again.</summary>
    public bool RevertSeason(out string? error)
    {
        error = null;
        if (!EnsureAttached()) { error = "Not attached."; return false; }
        if (!_season.Apply(SeasonChanger.Revert, out var err))
        {
            error = err ?? "Season revert failed.";
            _log.Error(error);
            return false;
        }
        LastError = null;
        return true;
    }

    // ===== XP grant (game's own AddTotalXP via shellcode) =====

    public bool GrantXp(uint amount, out string? error)
    {
        error = null;
        if (!EnsureAttached()) { error = "Not attached."; return false; }
        // Install the capture hook on first use; the owner arrives on the next
        // natural XP gain (any skill chain / race reward).
        if (!_engine.EnsureXpHook(out var hookErr))
        {
            error = $"XP hook: {hookErr}";
            _log.Error(error);
            return false;
        }
        if (!_xp.Grant(amount, out var err))
        {
            LastError = err;
            _log.Error($"XP grant: {err}");
            return false;
        }
        _log.Info($"Granted {amount} XP (game's own AddTotalXP path)");
        LastError = null;
        return true;
    }

    // ===== Weather (live intensity control) =====

    /// <summary>
    /// Installs the capture hook if needed and reads the current intensities.
    /// The entity is captured on the game's next frame — reading right after the
    /// first install may return null; the UI retries.
    /// </summary>
    public WeatherChanger.WeatherState? ReadWeather()
    {
        if (!EnsureAttached()) return null;
        if (!_weather.IsResolved && !_engine.EnsureWeatherHook(out var hookErr))
        {
            _log.Error($"Weather hook: {hookErr}");
            return null;
        }
        return _weather.ReadState();
    }

    public bool SetWeather(float rain, float wetness, float atmosphere, float wind, out string? error)
    {
        error = null;
        if (!EnsureAttached()) { error = "Not attached."; return false; }
        if (!_weather.IsResolved && !_engine.EnsureWeatherHook(out var hookErr))
        {
            error = $"Weather hook: {hookErr}";
            _log.Error(error);
            return false;
        }
        if (!_weather.SetState(rain, wetness, atmosphere, wind, out var setErr))
        {
            error = setErr;
            _log.Error(error);
            return false;
        }
        LastError = null;
        return true;
    }
}
