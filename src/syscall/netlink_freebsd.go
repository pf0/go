// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Netlink sockets and messages

package syscall

import (
	"sync"
	"unsafe"
)

const (
	FREEBSD_AF_NETLINK            = 38
	FREEBSD_NETLINK_ROUTE         = 0
	FREEBSD_SOCK_RAW              = 3
	FREEBSD_SOCK_CLOEXEC          = 0x10000000
	FREEBSD_SizeofSockaddrNetlink = 0xc

	FREEBSD_NLMSG_HDRLEN  = 0x10 //TODO: check if true
	FREEBSD_NLMSG_ALIGNTO = 4
	FREEBSD_NLMSG_ERROR   = 0x2 /* reply error code reporting */
	FREEBSD_NLMSG_DONE    = 0x3 /* Message terminates a multipart message. */

	FREEBSD_NL_RTM_GETADDR     = 22 /* lists matching ifaddrs */
	FREEBSD_NL_ITEM_ALIGN_SIZE = 4
	FREEBSD_NL_RTA_ALIGN_SIZE  = FREEBSD_NL_ITEM_ALIGN_SIZE
	FREEBSD_RTA_ALIGNTO        = FREEBSD_NL_RTA_ALIGN_SIZE

	FREEBSD_NLM_F_DUMP_INTR     = 0x10 /* Dump was inconsistent due to sequence change */
	FREEBSD_NLM_F_DUMP_FILTERED = 0x20 /* Dump was filtered as requested */
	FREEBSD_NLM_F_DUMP          = FREEBSD_NLM_F_DUMP_INTR | FREEBSD_NLM_F_DUMP_FILTERED
	FREEBSD_NLM_F_REQUEST       = 0x01

	FREEBSD_NL_RTM_NEWLINK  = 16 /* creates new interface */
	FREEBSD_NL_RTM_DELINK   = 17 /* deletes matching interface */
	FREEBSD_NL_RTM_NEWROUTE = 24 /* adds or changes a route */
	FREEBSD_NL_RTM_DELROUTE = 25 /* deletes matching route */
	FREEBSD_RTM_NEWLINK     = FREEBSD_NL_RTM_NEWLINK
	FREEBSD_RTM_DELINK      = FREEBSD_NL_RTM_DELINK
	FREEBSD_RTM_NEWROUTE    = FREEBSD_NL_RTM_NEWROUTE
	FREEBSD_RTM_DELROUTE    = FREEBSD_NL_RTM_DELROUTE

	FREEBSD_RTM_GETADDR = FREEBSD_NL_RTM_GETADDR

	SizeofRtGenmsg        = 0x1
	SizeofIfInfomsg       = 0x10
	SizeofRtAttr          = 0x4
	SizeofSockaddrNetlink = 0xc
	SizeofIfAddrmsg       = 0x8
	SizeofRtMsg           = 0xc

	IFA_ADDRESS = 1 /* binary, prefix address (destination for p2p) */
	IFA_LOCAL   = 2 /* binary, interface address */
)

// Round the length of a netlink message up to align it properly.
func nlmAlignOf(msglen int) int {
	return (msglen + FREEBSD_NLMSG_ALIGNTO - 1) & ^(FREEBSD_NLMSG_ALIGNTO - 1)
}

// Round the length of a netlink route attribute up to align it
// properly.
func rtaAlignOf(attrlen int) int {
	return (attrlen + FREEBSD_RTA_ALIGNTO - 1) & ^(FREEBSD_RTA_ALIGNTO - 1)
}

var pageBufPool = &sync.Pool{New: func() any {
	b := make([]byte, Getpagesize())
	return &b
}}

type RawSockaddrNetlinkFreeBSD struct {
	Family uint16
	Pad    uint16
	Pid    uint32
	Groups uint32
}

type SockaddrNetlinkFreeBSD struct {
	Family int
	Pad    uint16
	Pid    uint32
	Groups uint32
	raw    RawSockaddrNetlinkFreeBSD
}

func (sa *SockaddrNetlinkFreeBSD) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = FREEBSD_AF_NETLINK
	sa.raw.Pad = sa.Pad
	sa.raw.Pid = sa.Pid
	sa.raw.Groups = sa.Groups
	return unsafe.Pointer(&sa.raw), SizeofSockaddrNetlink, nil
}

// NetlinkRIB returns routing information base, as known as RIB, which
// consists of network facility information, states and parameters.
func NetlinkRIBFreeBSD(proto, family int) ([]byte, error) {
	s, err := Socket(FREEBSD_AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, FREEBSD_NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer Close(s)
	sa := &SockaddrNetlinkFreeBSD{Family: FREEBSD_AF_NETLINK}
	if err := Bind(s, sa); err != nil {
		return nil, err
	}
	wb := newNetlinkRouteRequest(proto, 1, family)
	if err := Sendto(s, wb, 0, sa); err != nil {
		return nil, err
	}
	lsa, err := Getsockname(s)
	if err != nil {
		return nil, err
	}
	lsanl, ok := lsa.(*SockaddrNetlinkFreeBSD)
	if !ok {
		return nil, EINVAL
	}
	var tab []byte

	rbNew := pageBufPool.Get().(*[]byte)
	defer pageBufPool.Put(rbNew)
done:
	for {
		rb := *rbNew
		nr, _, err := Recvfrom(s, rb, 0)
		if err != nil {
			return nil, err
		}
		if nr < FREEBSD_NLMSG_HDRLEN {
			return nil, EINVAL
		}
		rb = rb[:nr]
		tab = append(tab, rb...)
		msgs, err := ParseNetlinkMessageFreeBSD(rb)
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != 1 || m.Header.Pid != lsanl.Pid {
				return nil, EINVAL
			}
			if m.Header.Type == FREEBSD_NLMSG_DONE {
				break done
			}
			if m.Header.Type == FREEBSD_NLMSG_ERROR {
				return nil, EINVAL
			}
		}
	}
	return tab, nil
}

// NetlinkMessage represents a netlink message.
type NetlinkMessageFreeBSD struct {
	Header NlMsghdrFreeBSD
	Data   []byte
}

// ParseNetlinkMessage parses b as an array of netlink messages and
// returns the slice containing the NetlinkMessage structures.
func ParseNetlinkMessageFreeBSD(b []byte) ([]NetlinkMessageFreeBSD, error) {
	var msgs []NetlinkMessageFreeBSD
	for len(b) >= FREEBSD_NLMSG_HDRLEN {
		h, dbuf, dlen, err := netlinkMessageHeaderAndData(b)
		if err != nil {
			return nil, err
		}
		m := NetlinkMessageFreeBSD{Header: *h, Data: dbuf[:int(h.Len)-FREEBSD_NLMSG_HDRLEN]}
		msgs = append(msgs, m)
		b = b[dlen:]
	}
	return msgs, nil
}

func netlinkMessageHeaderAndData(b []byte) (*NlMsghdrFreeBSD, []byte, int, error) {
	h := (*NlMsghdrFreeBSD)(unsafe.Pointer(&b[0]))
	l := nlmAlignOf(int(h.Len))
	if int(h.Len) < FREEBSD_NLMSG_HDRLEN || l > len(b) {
		return nil, nil, 0, EINVAL
	}
	return h, b[FREEBSD_NLMSG_HDRLEN:], l, nil
}

type RtAttrFreeBSD struct {
	Len  uint16
	Type uint16
}

// NetlinkRouteAttr represents a netlink route attribute.
type NetlinkRouteAttrFreeBSD struct {
	Attr  RtAttrFreeBSD
	Value []byte
}

// ParseNetlinkRouteAttr parses m's payload as an array of netlink
// route attributes and returns the slice containing the
// NetlinkRouteAttr structures.
func ParseNetlinkRouteAttrFreeBSD(m *NetlinkMessageFreeBSD) ([]NetlinkRouteAttrFreeBSD, error) {
	var b []byte
	switch m.Header.Type {
	case FREEBSD_RTM_NEWLINK, FREEBSD_RTM_DELINK:
		b = m.Data[SizeofIfInfomsg:]
	case RTM_NEWADDR, RTM_DELADDR:
		b = m.Data[SizeofIfAddrmsg:]
	case FREEBSD_RTM_NEWROUTE, FREEBSD_RTM_DELROUTE:
		b = m.Data[SizeofRtMsg:]
	default:
		return nil, EINVAL
	}
	var attrs []NetlinkRouteAttrFreeBSD
	for len(b) >= SizeofRtAttr {
		a, vbuf, alen, err := netlinkRouteAttrAndValue(b)
		if err != nil {
			return nil, err
		}
		ra := NetlinkRouteAttrFreeBSD{Attr: *a, Value: vbuf[:int(a.Len)-SizeofRtAttr]}
		attrs = append(attrs, ra)
		b = b[alen:]
	}
	return attrs, nil
}

type NlMsghdrFreeBSD struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

type RtGenmsgFreeBSD struct {
	Family uint8
}

// NetlinkRouteRequest represents a request message to receive routing
// and link states from the kernel.
type NetlinkRouteRequestFreeBSD struct {
	Header NlMsghdrFreeBSD
	Data   RtGenmsgFreeBSD
}

func (rr *NetlinkRouteRequestFreeBSD) toWireFormat() []byte {
	b := make([]byte, rr.Header.Len)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
	b[16] = rr.Data.Family
	return b
}

func newNetlinkRouteRequest(proto, seq, family int) []byte {
	rr := &NetlinkRouteRequestFreeBSD{}
	rr.Header.Len = uint32(FREEBSD_NLMSG_HDRLEN + SizeofRtGenmsg)
	rr.Header.Type = uint16(proto)
	rr.Header.Flags = FREEBSD_NLM_F_DUMP | FREEBSD_NLM_F_REQUEST
	rr.Header.Seq = uint32(seq)
	rr.Data.Family = uint8(family)
	return rr.toWireFormat()
}

func netlinkRouteAttrAndValue(b []byte) (*RtAttrFreeBSD, []byte, int, error) {
	a := (*RtAttrFreeBSD)(unsafe.Pointer(&b[0]))
	if int(a.Len) < SizeofRtAttr || int(a.Len) > len(b) {
		return nil, nil, 0, EINVAL
	}
	return a, b[SizeofRtAttr:], rtaAlignOf(int(a.Len)), nil
}

type IfAddrmsgFreeBSD struct {
	Family    uint8
	Prefixlen uint8
	Flags     uint8
	Scope     uint8
	Index     uint32
}
