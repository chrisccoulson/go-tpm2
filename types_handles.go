// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import "fmt"

// This file contains types defined in section 7 (Handles) in
// part 2 of the library spec.

// Handle corresponds to the TPM_HANDLE type, and is a numeric
// identifier that references a resource on the TPM.
type Handle uint32

// Type returns the type of the handle.
func (h Handle) Type() HandleType {
	return HandleType(h >> 24)
}

// Base returns the first handle for the type of this handle (see [HandleType]).
func (h Handle) Base() Handle {
	return h.Type().BaseHandle()
}

// AsLoadedSession returns a handle that is appropriate to pass to TPM2_GetCapability
// in order to query the sessions that are currently loaded.
//
// Note that if you use the [TPMContext.DoesHandleExist] helper function, use of
// this is unnecessary.
//
// This will panic if the handle is not a session. Check this using [Handle.Type].
func (h Handle) AsLoadedSession() Handle {
	switch h.Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		return (h & 0xffffff) | (Handle(HandleTypeLoadedSession) << 24)
	default:
		panic(fmt.Sprintf("handle %v does not correspond to a session", h))
	}
}

// AsSavedSession returns a handle that is appropriate to pass to TPM2_GetCapability
// in order to query the sessions that are currently saved (ie, active but with no
// context stored in the TPM).
//
// Note that if you use the [TPMContext.DoesSavedSessionExist] helper function, use of
// this is unnecessary.
//
// This will panic if the handle is not a session. Check this using [Handle.Type].
func (h Handle) AsSavedSession() Handle {
	switch h.Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		return (h & 0xffffff) | (Handle(HandleTypeSavedSession) << 24)
	default:
		panic(fmt.Sprintf("handle %v does not correspond to a session", h))
	}
}

// SessionHandleMatches determines whether the supplied session handle corresponds
// to the same session that this handle corresponds to. This takes into account that
// sessions are identified by their lower 3 bytes and there can't be 2 sessions of
// different types with the same session ID.
//
// It's unlikely that one will use this directly. It is used internally to the
// [TPMContext.DoesSavedSessionExist] helper function.
//
// This will panic if this session or the supplied session are not both session
// handles. Check this using [Handle.Type].
func (h Handle) SessionHandleMatches(other Handle) bool {
	var hSessionId Handle
	switch h.Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		hSessionId = (h & 0xffffff)
	default:
		panic(fmt.Sprintf("handle %v does not correspond to a session", h))
	}

	var otherSessionId Handle
	switch other.Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		otherSessionId = (other & 0xffffff)
	default:
		panic(fmt.Sprintf("supplied handle %v does not correspond to a session", h))
	}

	return hSessionId == otherSessionId
}

// SupportsHierarchyFWOrSVNBinding indicates whether the current handle
// corresponds to a hierarchy that supports firmware or SVN binding.
func (h Handle) SupportsHierarchyFWOrSVNBinding() bool {
	return h.SupportsHierarchyFWBinding() || h.SupportsHierarchySVNBinding()
}

// BaseHierarchy returns the handle for the base hierarchy for any
// handle that corresponds to a firmware or SVN bound hierarchy or a
// hierarchy that supports these bindings. This will panic for any handle
// that doesn't correspond to a firmware or SVN bound hierarchy, a base
// hierarchy that doesn't supports firmware or SVN binding or any handle
// that doesn't correspond to a hierarchy. To check if the supplied handle
// corresponds to a hierarchy that supports firmware or SVN binding, use
// [Handle.SupportsHierarchyFWOrSVNBinding].
func (h Handle) BaseHierarchy() Handle {
	switch {
	case h.IsFWBoundHierarchy():
		switch h {
		case HandleFWOwner:
			return HandleOwner
		case HandleFWNull:
			return HandleNull
		case HandleFWEndorsement:
			return HandleEndorsement
		case HandleFWPlatform:
			return HandlePlatform
		}
	case h.IsSVNBoundHierarchy():
		switch h.SVNBaseHierarchy() {
		case HandleSVNOwnerBase:
			return HandleOwner
		case HandleSVNNullBase:
			return HandleNull
		case HandleSVNEndorsementBase:
			return HandleEndorsement
		case HandleSVNPlatformBase:
			return HandlePlatform
		}
	default:
		switch h {
		case HandleOwner, HandleNull, HandleEndorsement, HandlePlatform:
			return h
		}
	}

	panic(fmt.Sprintf("handle %v does not correspond to a hierarchy that supports firmware or SVN binding", h))
}

// IsFWBoundHierarchy indicates whether the handle corresponds to a firmware
// bound hierarchy, in which objects can only be accessed by the TPM firmware
// from which they were created.
func (h Handle) IsFWBoundHierarchy() bool {
	switch h {
	case HandleFWOwner, HandleFWNull, HandleFWEndorsement, HandleFWPlatform:
		return true
	default:
		return false
	}
}

// SupportsHierarchyFWBinding determines whether the current handle corresponds
// to a hierarchy that supports binding objects to a specific TPM firmware. One
// must still call [Handle.WithFWBinding] to obtain an appropriate handle
// that can be used to create primary keys that are bound to the current TPM
// firmware.
func (h Handle) SupportsHierarchyFWBinding() bool {
	switch h {
	case HandleOwner, HandleNull, HandleEndorsement, HandlePlatform:
		return true
	case HandleFWOwner, HandleFWNull, HandleFWEndorsement, HandleFWPlatform:
		return true
	default:
		return false
	}
}

// WithFWBinding returns a version of the current handle that supports firmware
// binding. If the current handle does not correspond to a hierarchy that supports
// firmware binding, this function will panic. To check if a handle corresponds
// to a hierachy that supports firmware binding, use [Handle.SupportsHierarchyFWBinding]
// first.
//
// Objects created in the returned hierarchy are only accessible to this hierarchy,
// using the TPM firmware from which they were created (ie, upgrading the TPM firmware
// invalidates all objects in the hierarchy that the returned handle corresponds to).
func (h Handle) WithFWBinding() Handle {
	switch h {
	case HandleOwner, HandleFWOwner:
		return HandleFWOwner
	case HandleNull, HandleFWNull:
		return HandleFWNull
	case HandleEndorsement, HandleFWEndorsement:
		return HandleFWEndorsement
	case HandlePlatform, HandleFWPlatform:
		return HandleFWPlatform
	default:
		panic(fmt.Sprintf("handle %v does not correspond to a hierarchy that supports firmware binding", h))
	}
}

// IsSVNBoundHierarchy indicates whether the handle corresponds to a SVN
// (security version number) bound hierarchy, in which objects created
// can only be accessed by TPM firmware using the same SVN bound hierarchy,
// if the SVN is supported by the current TPM firmware.
func (h Handle) IsSVNBoundHierarchy() bool {
	base := h & 0xffff0000
	switch base {
	case HandleSVNOwnerBase, HandleSVNEndorsementBase, HandleSVNPlatformBase, HandleSVNNullBase:
		return true
	default:
		return false
	}
}

// SupportsHierarchySVNBinding determines whether the current handle corresponds to a
// hierarchy that supports binding objects to a specific security version
// number (SVN). One must still call [Handle.WithSVNBinding] to obtain an
// appropriate handle for the SVN bound hierarchy that can be used to create
// primary keys that are bound to the desired SVN.
func (h Handle) SupportsHierarchySVNBinding() bool {
	switch h {
	case HandleOwner, HandleNull, HandleEndorsement, HandlePlatform:
		return true
	default:
		switch h & 0xffff0000 {
		case HandleSVNOwnerBase, HandleSVNNullBase, HandleSVNEndorsementBase, HandleSVNPlatformBase:
			return true
		default:
			return false
		}
	}
}

// WithSVNBinding returns a version of the current handle that supports SVN binding
// and is bound to the specified security version number. If the current handle does
// not correspond to a hierarchy that supports SVN binding, this function will panic.
// To check if a handle corresponds to a hierachy that supports SVN binding, use
// [Handle.SupportsHierarchySVNBinding] first.
//
// In general, the supplied SVN should correspond to the TPM firmware's current SVN.
//
// Objects created in the returned hierarchy are only accessible to this hierarchy,
// which requires a TPM firmware implementation with support for the specified SVN.
// TPM firmware implementations have a current SVN, indicating support for that SVN
// and previous SVNs. A TPM firmware does not have support for SVNs that are greater
// than the current SVN, and are therefore unable to access hierarchies associated with
// these SVNs.
//
// Upon a security event, a TPM firmware update may increase the current SVN. Whilst
// objects created in previous SVN bound hierarchies will remain accessible, objects
// created within the new SVN bound hierarchy (if they are created in a hierarchy
// associated with the current firmware's SVN) will be accessible to the updated
// firmware and future firmware only, but will not be accessible to older firmware in the
// event that the firmware is rolled back to a version with a lower current SVN.
func (h Handle) WithSVNBinding(svn uint16) Handle {
	var base Handle
	switch h {
	case HandleOwner:
		base = HandleSVNOwnerBase
	case HandleNull:
		base = HandleSVNNullBase
	case HandleEndorsement:
		base = HandleSVNEndorsementBase
	case HandlePlatform:
		base = HandleSVNPlatformBase
	default:
		switch h & 0xffff0000 {
		case HandleSVNOwnerBase, HandleSVNNullBase, HandleSVNEndorsementBase, HandleSVNPlatformBase:
			base = (h & 0xffff0000)
		default:
			panic(fmt.Sprintf("handle %v does not correspond to a hierarchy that supports SVN binding", h))
		}
	}

	return base + Handle(svn)
}

// SVNBaseHierarchy returns the base handle of the current SVN bound handle,
// omitting the actual SVN. This can be used to determine to determine which
// hierarchy that supports SVN binding that the current handle points to.
//
// This will panic if the handle does not correspond to a SVN bound hierarchy.
// Check this using [Handle.SupportsHierarchySVNBinding].
func (h Handle) SVNBaseHierarchy() Handle {
	base := h & 0xffff0000
	switch base {
	case HandleSVNOwnerBase, HandleSVNEndorsementBase, HandleSVNPlatformBase, HandleSVNNullBase:
		return base
	default:
		panic(fmt.Sprintf("handle %v does not correspond to a hierarchy that supports SVN binding", h))
	}
}

// SVN returns the security version number associated with the handle. This will
// panic if the handle does not correspond to a SVN bound hierarhcy. Check this
// using [Handle.SupportsHierarchySVNBinding].
func (h Handle) SVN() uint16 {
	// Force a panic if this handle doesn't correspond to a hierarchy that supports SVN binding,
	// as callers should use Handle.SupportsHierarchySVNBinding.
	h.SVNBaseHierarchy()
	return uint16(h & 0xffff)
}

const (
	HandleOwner              Handle = 0x40000001 // TPM_RH_OWNER
	HandleNull               Handle = 0x40000007 // TPM_RH_NULL
	HandleUnassigned         Handle = 0x40000008 // TPM_RH_UNASSIGNED
	HandlePW                 Handle = 0x40000009 // TPM_RS_PW
	HandleLockout            Handle = 0x4000000a // TPM_RH_LOCKOUT
	HandleEndorsement        Handle = 0x4000000b // TPM_RH_ENDORSEMENT
	HandlePlatform           Handle = 0x4000000c // TPM_RH_PLATFORM
	HandlePlatformNV         Handle = 0x4000000d // TPM_RH_PLATFORM_NV
	HandleFWOwner            Handle = 0x40000140 // TPM_RH_FW_OWNER
	HandleFWEndorsement      Handle = 0x40000141 // TPM_RH_FW_ENDORSEMENT
	HandleFWPlatform         Handle = 0x40000142 // TPM_RH_FW_PLATFORM
	HandleFWNull             Handle = 0x40000143 // TPM_RH_FW_NULL
	HandleSVNOwnerBase       Handle = 0x40010000 // TPM_RH_SVN_OWNER_BASE
	HandleSVNEndorsementBase Handle = 0x40020000 // TPM_RH_SVN_ENDORSEMENT_BASE
	HandleSVNPlatformBase    Handle = 0x40030000 // TPM_RH_SVN_PLATFORM_BASE
	HandleSVNNullBase        Handle = 0x40040000 // TPM_RH_SVN_NULL_BASE
)

// HandleType corresponds to the TPM_HT type, and is used to
// identify the type of a Handle.
type HandleType uint8

// BaseHandle returns the first handle for the handle type.
func (h HandleType) BaseHandle() Handle {
	return Handle(h) << 24
}

const (
	HandleTypePCR           HandleType = 0x00 // TPM_HT_PCR
	HandleTypeNVIndex       HandleType = 0x01 // TPM_HT_NV_INDEX
	HandleTypeHMACSession   HandleType = 0x02 // TPM_HT_HMAC_SESSION
	HandleTypeLoadedSession HandleType = 0x02 // TPM_HT_LOADED_SESSION
	HandleTypePolicySession HandleType = 0x03 // TPM_HT_POLICY_SESSION
	HandleTypeSavedSession  HandleType = 0x03 // TPM_HT_SAVED_SESSION
	HandleTypeExternalNV    HandleType = 0x11 // TPM_HT_EXTERNAL_NV
	HandleTypePermanentNV   HandleType = 0x12 // TPM_HT_PERMANENT_NV
	HandleTypePermanent     HandleType = 0x40 // TPM_HT_PERMANENT
	HandleTypeTransient     HandleType = 0x80 // TPM_HT_TRANSIENT
	HandleTypePersistent    HandleType = 0x81 // TPM_HT_PERSISTENT
	HandleTypeAC            HandleType = 0x90 // TPM_HT_AC
)
