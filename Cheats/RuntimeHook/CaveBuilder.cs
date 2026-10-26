using System;
using System.Collections.Generic;

namespace FH6Mod.Cheats.RuntimeHook;

/// <summary>
/// Minimal x64 code emitter for trainer code caves. Supports labels, rip-relative
/// references to data slots inside the cave, rel32 jumps to labels or to absolute
/// addresses, and absolute calls/loads through movabs. All displacements are resolved
/// against the final cave address in <see cref="Finish"/>, so the cave can be built
/// before or after the memory for it is allocated.
/// </summary>
internal sealed class CaveBuilder
{
    private readonly List<byte> _code = new();
    private readonly Dictionary<string, int> _labels = new(StringComparer.Ordinal);
    private readonly List<(int DispPos, int InstrEnd, string Label)> _labelFixups = new();
    private readonly List<(int DispPos, int InstrEnd, ulong Target)> _absFixups = new();

    public ulong BaseAddress { get; }
    public int Position => _code.Count;

    public CaveBuilder(ulong caveAddress) => BaseAddress = caveAddress;

    public void Label(string name)
    {
        if (_labels.ContainsKey(name))
            throw new InvalidOperationException($"Cave label '{name}' defined twice.");
        _labels[name] = _code.Count;
    }
    public int OffsetOf(string label) => _labels[label];
    public ulong AddressOf(string label) => BaseAddress + (ulong)_labels[label];

    public void Emit(params byte[] bytes) => _code.AddRange(bytes);

    // ----- absolute operands -----
    public void MovabsRax(ulong imm) { Emit(0x48, 0xB8); Emit(BitConverter.GetBytes(imm)); }
    public void MovabsRcx(ulong imm) { Emit(0x48, 0xB9); Emit(BitConverter.GetBytes(imm)); }
    /// <summary>rcx = *(ulong*)absAddress</summary>
    public void LoadRcxFromAbs(ulong absAddress) { MovabsRcx(absAddress); Emit(0x48, 0x8B, 0x09); }
    /// <summary>rax = fn ; call rax</summary>
    public void CallAbs(ulong fn) { MovabsRax(fn); Emit(0xFF, 0xD0); }

    // ----- rip-relative operands -----
    /// <summary>
    /// Emits <paramref name="opcode"/> + disp32 (to <paramref name="label"/>) + any trailing
    /// immediate bytes that belong to the same instruction. The displacement is computed
    /// from the end of the whole instruction, immediate included.
    /// </summary>
    public void RipRel(byte[] opcode, string label, params byte[] trailingImm)
    {
        Emit(opcode);
        var dispPos = _code.Count;
        Emit(0, 0, 0, 0);
        Emit(trailingImm);
        _labelFixups.Add((dispPos, _code.Count, label));
    }

    public void MovEaxFromRip(string label) => RipRel([0x8B, 0x05], label);          // mov eax,[rip+d]
    public void MovEdxFromRip(string label) => RipRel([0x8B, 0x15], label);          // mov edx,[rip+d]
    public void MovRdxFromRip(string label) => RipRel([0x48, 0x8B, 0x15], label);    // mov rdx,[rip+d]
    public void MovRipFromRax(string label) => RipRel([0x48, 0x89, 0x05], label);    // mov [rip+d],rax
    public void MovRipFromEax(string label) => RipRel([0x89, 0x05], label);          // mov [rip+d],eax
    public void MovRipDword(string label, int imm) => RipRel([0xC7, 0x05], label, BitConverter.GetBytes(imm));            // mov dword [rip+d],imm32
    public void MovRipQwordImm32(string label, int imm) => RipRel([0x48, 0xC7, 0x05], label, BitConverter.GetBytes(imm)); // mov qword [rip+d],simm32
    public void IncRipDword(string label) => RipRel([0xFF, 0x05], label);            // inc dword [rip+d]

    public void JmpRel32(string label) => RipRel([0xE9], label);
    /// <summary>cc: 0x84 je, 0x85 jne, 0x83 jae/jnb, 0x82 jb ...</summary>
    public void JccRel32(byte cc, string label) => RipRel([0x0F, cc], label);

    /// <summary>jmp rel32 to an absolute address (used for the jump back to the hook site).</summary>
    public void JmpAbs(ulong target)
    {
        Emit(0xE9);
        var dispPos = _code.Count;
        Emit(0, 0, 0, 0);
        _absFixups.Add((dispPos, _code.Count, target));
    }

    // ----- data slots -----
    /// <summary>Reserves an aligned, zero-initialised data slot and labels it.</summary>
    public void Data(string label, int size, int align = 8)
    {
        while (_code.Count % align != 0) _code.Add(0);
        Label(label);
        for (var i = 0; i < size; i++) _code.Add(0);
    }

    public void DataInt32(string label, int value)
    {
        Data(label, 4, 4);
        var bytes = BitConverter.GetBytes(value);
        for (var i = 0; i < 4; i++) _code[_labels[label] + i] = bytes[i];
    }

    public byte[] Finish()
    {
        var bytes = _code.ToArray();
        foreach (var (dispPos, instrEnd, label) in _labelFixups)
        {
            if (!_labels.TryGetValue(label, out var target))
                throw new InvalidOperationException($"Cave label '{label}' not defined.");
            BitConverter.GetBytes(target - instrEnd).CopyTo(bytes, dispPos);
        }
        foreach (var (dispPos, instrEnd, target) in _absFixups)
        {
            var rel = (long)target - (long)(BaseAddress + (ulong)instrEnd);
            if (rel < int.MinValue || rel > int.MaxValue)
                throw new InvalidOperationException("Cave jump out of rel32 range.");
            BitConverter.GetBytes((int)rel).CopyTo(bytes, dispPos);
        }
        return bytes;
    }
}
