// Copyright 2019-2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
)

type handlesSuite struct{}

var _ = Suite(&handlesSuite{})

func (s *handlesSuite) TestHandleTypePCR(c *C) {
	handle := Handle(0)
	c.Check(handle.Type(), Equals, HandleTypePCR)
}

func (s *handlesSuite) TestHandleTypeNVIndex(c *C) {
	handle := Handle(0x0180ff00)
	c.Check(handle.Type(), Equals, HandleTypeNVIndex)
}

func (s *handlesSuite) TestHandleTypeHMACSession(c *C) {
	handle := Handle(0x02000001)
	c.Check(handle.Type(), Equals, HandleTypeHMACSession)
}

func (s *handlesSuite) TestHandleTypePolicySession(c *C) {
	handle := Handle(0x03000001)
	c.Check(handle.Type(), Equals, HandleTypePolicySession)
}

func (s *handlesSuite) TestHandleTypePermanent(c *C) {
	handle := HandleOwner
	c.Check(handle.Type(), Equals, HandleTypePermanent)
}

func (s *handlesSuite) TestHandleTypeTransient(c *C) {
	handle := Handle(0x80000003)
	c.Check(handle.Type(), Equals, HandleTypeTransient)
}

func (s *handlesSuite) TestHandleTypePersistent(c *C) {
	handle := Handle(0x81000001)
	c.Check(handle.Type(), Equals, HandleTypePersistent)
}

func (s *handlesSuite) TestHandleBase1(c *C) {
	handle := Handle(0x80000003)
	c.Check(handle.Base(), Equals, Handle(0x80000000))
}

func (s *handlesSuite) TestHandleBase2(c *C) {
	handle := Handle(0x0180ff00)
	c.Check(handle.Base(), Equals, Handle(0x01000000))
}

func (s *handlesSuite) TestHandleAsLoadedSessionHMAC(c *C) {
	handle := Handle(0x02000001)
	c.Check(handle.AsLoadedSession(), Equals, handle)
}

func (s *handlesSuite) TestHandleAsLoadedSessionPolicy(c *C) {
	handle := Handle(0x03000002)
	c.Check(handle.AsLoadedSession(), Equals, Handle(0x02000002))
}

func (s *handlesSuite) TestHandleAsLoadedSessionInvalid(c *C) {
	handle := Handle(0x0180ff00)
	c.Check(func() { handle.AsLoadedSession() }, PanicMatches, `handle 0x0180ff00 does not correspond to a session`)
}

func (s *handlesSuite) TestHandleAsSavedSessionPolicy(c *C) {
	handle := Handle(0x03000001)
	c.Check(handle.AsSavedSession(), Equals, handle)
}

func (s *handlesSuite) TestHandleAsSavedSessionHMAC(c *C) {
	handle := Handle(0x02000002)
	c.Check(handle.AsSavedSession(), Equals, Handle(0x03000002))
}

func (s *handlesSuite) TestHandleAsSavedSessionInvalid(c *C) {
	handle := HandleOwner
	c.Check(func() { handle.AsSavedSession() }, PanicMatches, `handle TPM_RH_OWNER does not correspond to a session`)
}

func (s *handlesSuite) TestHandleSessionHandleMatchesTrue1(c *C) {
	handle := Handle(0x02000001)
	c.Check(handle.SessionHandleMatches(0x03000001), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSessionHandleMatchesTrue2(c *C) {
	handle := Handle(0x03000002)
	c.Check(handle.SessionHandleMatches(0x02000002), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSessionHandleMatchesTrue3(c *C) {
	handle := Handle(0x02000002)
	c.Check(handle.SessionHandleMatches(0x02000002), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSessionHandleMatchesFalse1(c *C) {
	handle := Handle(0x02000001)
	c.Check(handle.SessionHandleMatches(0x03000002), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleSessionHandleMatchesFalse2(c *C) {
	handle := Handle(0x03000002)
	c.Check(handle.SessionHandleMatches(0x02000001), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleSessionHandleMatchesFalse3(c *C) {
	handle := Handle(0x02000001)
	c.Check(handle.SessionHandleMatches(0x02000002), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleSessionHandleMatchesInvalid(c *C) {
	handle := HandlePW
	c.Check(func() { handle.SessionHandleMatches(0x02000000) }, PanicMatches, `handle TPM_RS_PW does not correspond to a session`)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingFWOwner(c *C) {
	c.Check(HandleFWOwner.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingFWEndorsement(c *C) {
	c.Check(HandleFWEndorsement.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingFWPlatform(c *C) {
	c.Check(HandleFWPlatform.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingFWNull(c *C) {
	c.Check(HandleFWNull.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingSVNOwner(c *C) {
	handle := HandleSVNOwnerBase + Handle(50)
	c.Check(handle.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingSVNEndorsement(c *C) {
	handle := HandleSVNEndorsementBase + Handle(5)
	c.Check(handle.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingSVNPlatform(c *C) {
	handle := HandleSVNPlatformBase
	c.Check(handle.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingSVNNull(c *C) {
	handle := HandleSVNNullBase + Handle(60)
	c.Check(handle.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingOwner(c *C) {
	c.Check(HandleOwner.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingEndorsement(c *C) {
	c.Check(HandleEndorsement.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingPlatform(c *C) {
	c.Check(HandlePlatform.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingNull(c *C) {
	c.Check(HandleNull.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingFalse1(c *C) {
	c.Check(HandleLockout.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWOrSVNBindingFalse2(c *C) {
	c.Check(HandlePW.SupportsHierarchyFWOrSVNBinding(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleBaseHierarchy1(c *C) {
	handle := HandleFWOwner
	c.Check(handle.BaseHierarchy(), Equals, HandleOwner)
}

func (s *handlesSuite) TestHandleBaseHierarchy2(c *C) {
	handle := HandleSVNEndorsementBase + Handle(5)
	c.Check(handle.BaseHierarchy(), Equals, HandleEndorsement)
}

func (s *handlesSuite) TestHandleBaseHierarchy3(c *C) {
	handle := HandlePlatform
	c.Check(handle.BaseHierarchy(), Equals, handle)
}

func (s *handlesSuite) TestHandleBaseHierarchyInvalid(c *C) {
	c.Check(func() { HandlePW.BaseHierarchy() }, PanicMatches, `handle TPM_RS_PW does not correspond to a hierarchy that supports firmware or SVN binding`)
}

func (s *handlesSuite) TestHandleIsFWBoundHierarchyFWOwner(c *C) {
	c.Check(HandleFWOwner.IsFWBoundHierarchy(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleIsFWBoundHierarchyFWEndorsement(c *C) {
	c.Check(HandleFWEndorsement.IsFWBoundHierarchy(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleIsFWBoundHierarchyFWPlatform(c *C) {
	c.Check(HandleFWPlatform.IsFWBoundHierarchy(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleIsFWBoundHierarchyFWNull(c *C) {
	c.Check(HandleFWNull.IsFWBoundHierarchy(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleIsFWBoundHierarchyFalseOwner(c *C) {
	c.Check(HandleOwner.IsFWBoundHierarchy(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleIsFWBoundHierarchyFalseEndorsment(c *C) {
	c.Check(HandleEndorsement.IsFWBoundHierarchy(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleIsFWBoundHierarchyFalseSVNOwner(c *C) {
	c.Check(HandleSVNOwnerBase.IsFWBoundHierarchy(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWBindingOwner(c *C) {
	c.Check(HandleOwner.SupportsHierarchyFWBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWBindingEndorsement(c *C) {
	c.Check(HandleEndorsement.SupportsHierarchyFWBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWBindingNull(c *C) {
	c.Check(HandleNull.SupportsHierarchyFWBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWBindingPlatform(c *C) {
	c.Check(HandlePlatform.SupportsHierarchyFWBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWBindingFWOwner(c *C) {
	c.Check(HandleFWOwner.SupportsHierarchyFWBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWBindingFWEndorsement(c *C) {
	c.Check(HandleFWEndorsement.SupportsHierarchyFWBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWBindingFWNull(c *C) {
	c.Check(HandleFWNull.SupportsHierarchyFWBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWBindingFWPlatform(c *C) {
	c.Check(HandleFWPlatform.SupportsHierarchyFWBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWBindingFalse1(c *C) {
	c.Check(HandleLockout.SupportsHierarchyFWBinding(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWBindingFalse2(c *C) {
	c.Check(HandlePW.SupportsHierarchyFWBinding(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleSupportsHierarchyFWBindingFalse3(c *C) {
	c.Check(HandleSVNOwnerBase.SupportsHierarchyFWBinding(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleWithFWBindingOwner(c *C) {
	c.Check(HandleOwner.WithFWBinding(), Equals, HandleFWOwner)
}

func (s *handlesSuite) TestHandleWithFWBindingEndorsement(c *C) {
	c.Check(HandleEndorsement.WithFWBinding(), Equals, HandleFWEndorsement)
}

func (s *handlesSuite) TestHandleWithFWBindingNull(c *C) {
	c.Check(HandleNull.WithFWBinding(), Equals, HandleFWNull)
}

func (s *handlesSuite) TestHandleWithFWBindingPlatform(c *C) {
	c.Check(HandlePlatform.WithFWBinding(), Equals, HandleFWPlatform)
}

func (s *handlesSuite) TestHandleWithFWBindingFWOwner(c *C) {
	c.Check(HandleFWOwner.WithFWBinding(), Equals, HandleFWOwner)
}

func (s *handlesSuite) TestHandleWithFWBindingFWEndorsement(c *C) {
	c.Check(HandleFWEndorsement.WithFWBinding(), Equals, HandleFWEndorsement)
}

func (s *handlesSuite) TestHandleWithFWBindingFWNull(c *C) {
	c.Check(HandleFWNull.WithFWBinding(), Equals, HandleFWNull)
}

func (s *handlesSuite) TestHandleWithFWBindingFWPlatform(c *C) {
	c.Check(HandleFWPlatform.WithFWBinding(), Equals, HandleFWPlatform)
}

func (s *handlesSuite) TestHandleIsSVNBoundHierarchSVNOwner(c *C) {
	handle := HandleSVNOwnerBase + Handle(10)
	c.Check(handle.IsSVNBoundHierarchy(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleIsSVNBoundHierarchySVNEndorsement(c *C) {
	handle := HandleSVNEndorsementBase + Handle(4)
	c.Check(handle.IsSVNBoundHierarchy(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleIsSVNBoundHierarchySVNPlatform(c *C) {
	handle := HandleSVNPlatformBase + Handle(15)
	c.Check(handle.IsSVNBoundHierarchy(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleIsSVNBoundHierarchySVNNull(c *C) {
	handle := HandleSVNNullBase + Handle(2)
	c.Check(handle.IsSVNBoundHierarchy(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleIsSVNBoundHierarchyFalseOwner(c *C) {
	c.Check(HandleOwner.IsSVNBoundHierarchy(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleIsSVNBoundHierarchyFalseEndorsment(c *C) {
	c.Check(HandleEndorsement.IsSVNBoundHierarchy(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleIsSVNBoundHierarchyFalseFWOwner(c *C) {
	c.Check(HandleFWOwner.IsSVNBoundHierarchy(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleSupportsHierarchySVNBindingOwner(c *C) {
	c.Check(HandleOwner.SupportsHierarchySVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchySVNBindingEndorsement(c *C) {
	c.Check(HandleEndorsement.SupportsHierarchySVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchySVNBindingNull(c *C) {
	c.Check(HandleNull.SupportsHierarchySVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchySVNBindingPlatform(c *C) {
	c.Check(HandlePlatform.SupportsHierarchySVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchySVNBindingSVNOwner(c *C) {
	handle := HandleSVNOwnerBase + Handle(10)
	c.Check(handle.SupportsHierarchySVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchySVNBindingSVNEndorsement(c *C) {
	handle := HandleSVNEndorsementBase + Handle(4)
	c.Check(handle.SupportsHierarchySVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchySVNBindingSVNNull(c *C) {
	handle := HandleSVNNullBase + Handle(2)
	c.Check(handle.SupportsHierarchySVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchySVNBindingSVNPlatform(c *C) {
	handle := HandleSVNPlatformBase + Handle(15)
	c.Check(handle.SupportsHierarchySVNBinding(), internal_testutil.IsTrue)
}

func (s *handlesSuite) TestHandleSupportsHierarchySVNBindingFalse1(c *C) {
	c.Check(HandleLockout.SupportsHierarchySVNBinding(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleSupportsHierarchySVNBindingFalse2(c *C) {
	c.Check(HandlePW.SupportsHierarchySVNBinding(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleSupportsHierarchySVNBindingFalse3(c *C) {
	c.Check(HandleFWOwner.SupportsHierarchySVNBinding(), internal_testutil.IsFalse)
}

func (s *handlesSuite) TestHandleWithSVNBindingOwner(c *C) {
	c.Check(HandleOwner.WithSVNBinding(10), Equals, HandleSVNOwnerBase+Handle(10))
}

func (s *handlesSuite) TestHandleWithSVNBindingEndorsement(c *C) {
	c.Check(HandleEndorsement.WithSVNBinding(5), Equals, HandleSVNEndorsementBase+Handle(5))
}

func (s *handlesSuite) TestHandleWithSVNBindingPlatform(c *C) {
	c.Check(HandlePlatform.WithSVNBinding(15), Equals, HandleSVNPlatformBase+Handle(15))
}

func (s *handlesSuite) TestHandleWithSVNBindingNull(c *C) {
	c.Check(HandleNull.WithSVNBinding(20), Equals, HandleSVNNullBase+Handle(20))
}

func (s *handlesSuite) TestHandleWithSVNBindingSVNOwner(c *C) {
	c.Check(HandleSVNOwnerBase.WithSVNBinding(5), Equals, HandleSVNOwnerBase+Handle(5))
}

func (s *handlesSuite) TestHandleWithSVNBindingSVNEndorsement(c *C) {
	c.Check(HandleSVNEndorsementBase.WithSVNBinding(10), Equals, HandleSVNEndorsementBase+Handle(10))
}

func (s *handlesSuite) TestHandleWithSVNBindingSVNPlatform(c *C) {
	c.Check(HandleSVNPlatformBase.WithSVNBinding(50), Equals, HandleSVNPlatformBase+Handle(50))
}

func (s *handlesSuite) TestHandleWithSVNBindingSVNNull(c *C) {
	c.Check(HandleSVNNullBase.WithSVNBinding(25), Equals, HandleSVNNullBase+Handle(25))
}

func (s *handlesSuite) TestHandleWithSVNBindingInvalid(c *C) {
	c.Check(func() { HandleLockout.WithSVNBinding(10) }, PanicMatches, `handle TPM_RH_LOCKOUT does not correspond to a hierarchy that supports SVN binding`)
}

func (s *handlesSuite) TestHandleSVNBaseHierarchyOwner(c *C) {
	handle := Handle(0x40010010)
	c.Check(handle.SVNBaseHierarchy(), Equals, HandleSVNOwnerBase)
}

func (s *handlesSuite) TestHandleSVNBaseHierarchyEndorsement(c *C) {
	handle := Handle(0x40020030)
	c.Check(handle.SVNBaseHierarchy(), Equals, HandleSVNEndorsementBase)
}

func (s *handlesSuite) TestHandleSVNBaseHierarchyPlatform(c *C) {
	handle := Handle(0x40030001)
	c.Check(handle.SVNBaseHierarchy(), Equals, HandleSVNPlatformBase)
}

func (s *handlesSuite) TestHandleSVNBaseHierarchyNull(c *C) {
	handle := Handle(0x40040025)
	c.Check(handle.SVNBaseHierarchy(), Equals, HandleSVNNullBase)
}

func (s *handlesSuite) TestHandleSVNBaseHierarchyInvalid(c *C) {
	handle := Handle(0x40050010)
	c.Check(func() { handle.SVNBaseHierarchy() }, PanicMatches, `handle 0x40050010 does not correspond to a hierarchy that supports SVN binding`)
}

func (s *handlesSuite) TestHandleSVNOwner(c *C) {
	handle := Handle(0x40010010)
	c.Check(handle.SVN(), Equals, uint16(16))
}

func (s *handlesSuite) TestHandleSVNEndorsement(c *C) {
	handle := Handle(0x40020030)
	c.Check(handle.SVN(), Equals, uint16(48))
}

func (s *handlesSuite) TestHandleSVNPlatform(c *C) {
	handle := Handle(0x40030001)
	c.Check(handle.SVN(), Equals, uint16(1))
}

func (s *handlesSuite) TestHandleSVNNull(c *C) {
	handle := Handle(0x40040025)
	c.Check(handle.SVN(), Equals, uint16(37))
}

func (s *handlesSuite) TestHandleInvalid(c *C) {
	c.Check(func() { HandleOwner.SVN() }, PanicMatches, `handle TPM_RH_OWNER does not correspond to a hierarchy that supports SVN binding`)
}
