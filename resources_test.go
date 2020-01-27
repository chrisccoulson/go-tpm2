// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"testing"
)

func TestGetOrCreateResourceContext(t *testing.T) {
	tpm := openTPMForTesting(t)
	closed := false
	defer func() {
		if closed {
			return
		}
		closeTPM(t, tpm)
	}()

	primary := createRSASrkForTesting(t, tpm, nil)
	defer verifyContextFlushed(t, tpm, primary)
	primaryHandle := primary.Handle()

	persistentHandle := Handle(0x81000008)
	persistentPrimary := persistObjectForTesting(t, tpm, tpm.OwnerHandleContext(), primary, persistentHandle)
	defer verifyPersistentObjectEvicted(t, tpm, tpm.OwnerHandleContext(), persistentPrimary)

	closeTPM(t, tpm)
	closed = true
	if primary.Handle() != HandleUnassigned || persistentPrimary.Handle() != HandleUnassigned {
		t.Fatalf("Expected resource contexts to be invalid")
	}

	tpm = openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary, err := tpm.GetOrCreateResourceContext(primaryHandle)
	if err != nil {
		t.Errorf("GetOrCreateResourceContext failed with a live transient object: %v", err)
	}
	if primary == nil {
		t.Fatalf("GetOrCreateResourceContext returned a nil pointer for a live transient object")
	}
	if primary.Handle() != primaryHandle {
		t.Errorf("GetOrCreateResourceContext returned an invalid context for a live transient object")
	}
	defer flushContext(t, tpm, primary)

	persistentPrimary, err = tpm.GetOrCreateResourceContext(persistentHandle)
	if err != nil {
		t.Errorf("GetOrCreateResourceContext failed with a live persistent object: %v", err)
	}
	if persistentPrimary == nil {
		t.Fatalf("GetOrCreateResourceContext returned a nil pointer for a live persistent object")
	}
	if persistentPrimary.Handle() != persistentHandle {
		t.Errorf("GetOrCreateResourceContext returned an invalid context for a live persistent object")
	}
	defer evictPersistentObject(t, tpm, tpm.OwnerHandleContext(), persistentPrimary)

	nvPub := NVPublic{
		Index:   0x018100ff,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite, NVTypeOrdinary),
		Size:    8}
	if err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPub, nil); err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	index, err := tpm.GetOrCreateResourceContext(nvPub.Index)
	if err != nil {
		t.Errorf("GetOrCreateResourceContext failed with a live NV index: %v", err)
	}
	if index == nil {
		t.Fatalf("GetOrCreateResourceContext returned a nil pointer for a live NV index")
	}
	if index.Handle() != nvPub.Index {
		t.Errorf("GetOrCreateResourceContext returned an invalid context for a live NV index")
	}
	defer undefineNVSpace(t, tpm, index, tpm.OwnerHandleContext(), nil)

	_, err = tpm.GetOrCreateResourceContext(primaryHandle + 1)
	if err == nil {
		t.Fatalf("GetOrCreateResourceContext should return an error for a dead transient object")
	}
	if e, ok := err.(ResourceUnavailableError); !ok || e.Handle != primaryHandle+1 {
		t.Errorf("GetOrCreateResourceContext returned an unexpected error for a dead transient object: %v", err)
	}
	_, err = tpm.GetOrCreateResourceContext(persistentHandle + 1)
	if err == nil {
		t.Fatalf("GetOrCreateResourceContext should return an error for a dead persistent object")
	}
	if e, ok := err.(ResourceUnavailableError); !ok || e.Handle != persistentHandle+1 {
		t.Errorf("GetOrCreateResourceContext returned an unexpected error for a dead persistent object: %v", err)
	}
	_, err = tpm.GetOrCreateResourceContext(nvPub.Index + 1)
	if err == nil {
		t.Fatalf("GetOrCreateResourceContext should return an error for a dead NV index")
	}
	if e, ok := err.(ResourceUnavailableError); !ok || e.Handle != nvPub.Index+1 {
		t.Errorf("GetOrCreateResourceContext returned an unexpected error for a dead NV index: %v", err)
	}
}

func TestGetOrCreateSessionContext(t *testing.T) {
	tpm := openTPMForTesting(t)
	closed := false
	defer func() {
		if closed {
			return
		}
		closeTPM(t, tpm)
	}()

	sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer verifyContextFlushed(t, tpm, sessionContext)
	sessionHandle := sessionContext.Handle()

	if rc, err := tpm.GetOrCreateSessionContext(sessionHandle); err != nil {
		t.Errorf("GetOrCreateSessionContext failed: %v", err)
	} else if rc != sessionContext {
		t.Errorf("GetOrCreateSessionContext returned the wrong context")
	}

	savedSessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer verifyContextFlushed(t, tpm, savedSessionContext)
	savedSessionHandle := savedSessionContext.Handle()

	if _, err := tpm.ContextSave(savedSessionContext); err != nil {
		t.Fatalf("ContextSave failed: %v", err)
	}

	if rc, err := tpm.GetOrCreateSessionContext(savedSessionHandle); err != nil {
		t.Errorf("GetOrCreateSessionContext failed: %v", err)
	} else if rc != savedSessionContext {
		t.Errorf("GetOrCreateSessionContext returned the wrong context")
	}

	closeTPM(t, tpm)
	closed = true
	if sessionContext.Handle() != HandleUnassigned || savedSessionContext.Handle() != HandleUnassigned {
		t.Fatalf("Expected session contexts to be invalid")
	}

	tpm = openTPMForTesting(t)
	defer closeTPM(t, tpm)

	sessionContext, err = tpm.GetOrCreateSessionContext(sessionHandle)
	if err != nil {
		t.Errorf("GetOrCreateSessionContext failed with a loaded session: %v", err)
	}
	if sessionContext == nil {
		t.Fatalf("GetOrCreateSessionContext returned a nil pointer for a loaded session")
	}
	if sessionContext.Handle() != sessionHandle {
		t.Errorf("GetOrCreateSessionContext returned an invalid context for a loaded session")
	}
	defer flushContext(t, tpm, sessionContext)

	savedSessionContext, err = tpm.GetOrCreateSessionContext(savedSessionHandle)
	if err != nil {
		t.Errorf("GetOrCreateSessionContext failed with a saved session: %v", err)
	}
	if savedSessionContext == nil {
		t.Fatalf("GetOrCreateSessionContext returned a nil pointer for a saved session")
	}
	if savedSessionContext.Handle().Type() != HandleTypeHMACSession {
		t.Errorf("GetOrCreateSessionContext returned a context with an invalid handle type for a saved session")
	}
	if savedSessionContext.Handle()&0x00ffffff != savedSessionHandle&0x00ffffff {
		t.Errorf("GetOrCreateSessionContext returned an invalid context for a saved session")
	}
	defer flushContext(t, tpm, savedSessionContext)

}
