// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayguard

import (
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// The private pins and both TC attachments share one map. The owner occupies
// all 128 bits of the deployment journal's random owner token.
type value struct {
	Lock, Pad                              uint32
	Deadline, Generation, OwnerLo, OwnerHi uint64
}

func mapSpec(owner Owner) *ebpf.MapSpec {
	u32 := &btf.Int{Name: "unsigned int", Size: 4, Encoding: btf.Unsigned}
	u64 := &btf.Int{Name: "unsigned long long", Size: 8, Encoding: btf.Unsigned}
	lock := &btf.Struct{Name: "bpf_spin_lock", Size: 4, Members: []btf.Member{{Name: "val", Type: u32}}}
	return &ebpf.MapSpec{Name: owner.name(), Type: ebpf.Array, KeySize: 4, ValueSize: 40, MaxEntries: 1, Key: u32,
		Value: &btf.Struct{Name: "vpnctl_lease", Size: 40, Members: []btf.Member{
			{Name: "lock", Type: lock}, {Name: "pad", Type: u32, Offset: 32},
			{Name: "deadline", Type: u64, Offset: 64}, {Name: "generation", Type: u64, Offset: 128},
			{Name: "owner_lo", Type: u64, Offset: 192}, {Name: "owner_hi", Type: u64, Offset: 256}}}}
}

func lookup(fd int) asm.Instructions {
	return asm.Instructions{
		asm.StoreImm(asm.RFP, -36, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, fd), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -36),
		asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "drop"), asm.Mov.Reg(asm.R6, asm.R0),
		asm.FnKtimeGetBootNs.Call(), asm.Mov.Reg(asm.R8, asm.R0),
		asm.Mov.Reg(asm.R1, asm.R6), asm.FnSpinLock.Call(),
		asm.Mov.Imm(asm.R9, 2), // TC_ACT_SHOT; also failure for the unattached control program.
	}
}

func ownerCheck(owner Owner) asm.Instructions {
	lo, hi := owner.words()
	return asm.Instructions{
		asm.LoadMem(asm.R1, asm.R6, 24, asm.DWord), asm.LoadImm(asm.R2, int64(lo), asm.DWord), asm.JNE.Reg(asm.R1, asm.R2, "unlock"),
		asm.LoadMem(asm.R1, asm.R6, 32, asm.DWord), asm.LoadImm(asm.R2, int64(hi), asm.DWord), asm.JNE.Reg(asm.R1, asm.R2, "unlock"),
	}
}

func finish() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("unlock"), asm.FnSpinUnlock.Call(),
		asm.Mov.Reg(asm.R0, asm.R9), asm.Return(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("drop"), asm.Return(),
	}
}

func gateSpec(owner Owner, fd int) *ebpf.ProgramSpec {
	i := lookup(fd)
	i = append(i, ownerCheck(owner)...)
	i = append(i, asm.LoadMem(asm.R1, asm.R6, 8, asm.DWord), asm.JGE.Reg(asm.R8, asm.R1, "unlock"), asm.Mov.Imm(asm.R9, 0))
	i = append(i, finish()...)
	return &ebpf.ProgramSpec{Name: owner.name(), Type: ebpf.SchedCLS, License: "Dual BSD/GPL", Instructions: i}
}

// This program is never attached to a packet hook. Only BPF_PROG_TEST_RUN on
// its private FD supplies a proposal. A network packet cannot renew a lease.
// One spin-locked kernel operation checks the previous deadline/generation,
// fresh-response window, and immutable proposed deadline before updating it.
func controlSpec(owner Owner, fd int) *ebpf.ProgramSpec {
	i := asm.Instructions{
		// TestRun supplies a synthetic Ethernet header followed by 32 bytes.
		asm.Mov.Imm(asm.R2, 14), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32), asm.Mov.Imm(asm.R4, 32),
		asm.FnSkbLoadBytes.Call(), asm.JNE.Imm(asm.R0, 0, "drop"),
	}
	i = append(i, lookup(fd)...)
	i = append(i, ownerCheck(owner)...)
	i = append(i,
		asm.LoadMem(asm.R1, asm.R6, 16, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord), asm.JNE.Reg(asm.R1, asm.R2, "unlock"),
		asm.LoadImm(asm.R2, -1, asm.DWord), asm.JEq.Reg(asm.R1, asm.R2, "unlock"), // Never wrap the replay fence.
		asm.LoadMem(asm.R3, asm.RFP, -32, asm.DWord), asm.JEq.Imm(asm.R3, 0, "store"), // Revocation always closes.
		asm.JLE.Reg(asm.R3, asm.R8, "unlock"),
		asm.LoadImm(asm.R2, int64(MaxLease), asm.DWord), asm.Add.Reg(asm.R2, asm.R8), asm.JGT.Reg(asm.R3, asm.R2, "unlock"),
		asm.LoadMem(asm.R2, asm.R6, 8, asm.DWord), asm.JGT.Reg(asm.R2, asm.R8, "store"),
		asm.LoadMem(asm.R4, asm.RFP, -24, asm.DWord), asm.JLE.Reg(asm.R4, asm.R8, "unlock"),
		asm.LoadImm(asm.R2, int64(RearmWindow), asm.DWord), asm.Add.Reg(asm.R2, asm.R8), asm.JGT.Reg(asm.R4, asm.R2, "unlock"),
		asm.JGT.Reg(asm.R3, asm.R4, "unlock"),
		asm.StoreMem(asm.R6, 8, asm.R3, asm.DWord).WithSymbol("store"),
		asm.Add.Imm(asm.R1, 1), asm.StoreMem(asm.R6, 16, asm.R1, asm.DWord), asm.Mov.Imm(asm.R9, 0),
	)
	i = append(i, finish()...)
	return &ebpf.ProgramSpec{Name: "vl_update", Type: ebpf.SchedCLS, License: "Dual BSD/GPL", Instructions: i}
}

func proposal(deadline, freshUntil, generation uint64) []byte {
	b := make([]byte, 14+32)
	b[12], b[13] = 0x08, 0x00
	binary.NativeEndian.PutUint64(b[14:], deadline)
	binary.NativeEndian.PutUint64(b[22:], freshUntil)
	binary.NativeEndian.PutUint64(b[30:], generation)
	return b
}
