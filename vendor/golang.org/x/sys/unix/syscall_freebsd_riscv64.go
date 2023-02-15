// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build riscv64 && freebsd
// +build riscv64,freebsd

package unix

import (
	"syscall"
	"unsafe"
)

func setTimespec(sec, nsec int64) Timespec {
	return Timespec{Sec: sec, Nsec: nsec}
}

func setTimeval(sec, usec int64) Timeval {
	return Timeval{Sec: sec, Usec: usec}
}

func SetKevent(k *Kevent_t, fd, mode, flags int) {
	k.Ident = uint64(fd)
	k.Filter = int16(mode)
	k.Flags = uint16(flags)
}

func (iov *Iovec) SetLen(length int) {
	iov.Len = uint64(length)
}

func (msghdr *Msghdr) SetControllen(length int) {
	msghdr.Controllen = uint32(length)
}

func (msghdr *Msghdr) SetIovlen(length int) {
	msghdr.Iovlen = int32(length)
}

func (cmsg *Cmsghdr) SetLen(length int) {
	cmsg.Len = uint32(length)
}

func sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	var writtenOut uint64 = 0
	_, _, e1 := Syscall9(SYS_SENDFILE, uintptr(infd), uintptr(outfd), uintptr(*offset), uintptr(count), 0, uintptr(unsafe.Pointer(&writtenOut)), 0, 0, 0)

	written = int(writtenOut)

	if e1 != 0 {
		err = e1
	}
	return
}

func Syscall9(num, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err syscall.Errno)

<<<<<<< HEAD
func PtraceIO(req int, pid int, offs uintptr, out []byte, countin int) (count int, err error) {
	ioDesc := PtraceIoDesc{
		Op:   int32(req),
		Offs: offs,
		Addr: uintptr(unsafe.Pointer(&out[0])), // TODO(#58351): this is not safe.
		Len:  uint64(countin),
	}
=======
func PtraceIO(req int, pid int, addr uintptr, out []byte, countin int) (count int, err error) {
	ioDesc := PtraceIoDesc{Op: int32(req), Offs: uintptr(unsafe.Pointer(addr)), Addr: uintptr(unsafe.Pointer(&out[0])), Len: uint64(countin)}
>>>>>>> 0ab9102 (NETOBSERV-868: Update to use cilium auto generated golang structures (#90))
	err = ptrace(PT_IO, pid, uintptr(unsafe.Pointer(&ioDesc)), 0)
	return int(ioDesc.Len), err
}
