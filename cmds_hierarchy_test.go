// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"testing"
)

func TestCreatePrimary(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, hierarchy Handle, sensitive *SensitiveCreate, template *Public, outsideInfo Data,
		creationPCR PCRSelectionList, session interface{}) (HandleContext, *Public) {
		h, _ := tpm.WrapHandle(hierarchy)
		objectContext, outPublic, creationData, creationHash, creationTicket, name, err := tpm.CreatePrimary(h, sensitive, template, outsideInfo, creationPCR, session)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}

		if objectContext.Handle().Type() != HandleTypeTransient {
			t.Errorf("CreatePrimary returned an invalid handle 0x%08x", objectContext.Handle())
		}
		verifyPublicAgainstTemplate(t, outPublic, template)
		verifyCreationData(t, tpm, creationData, creationHash, template, outsideInfo, creationPCR, h)
		verifyCreationTicket(t, creationTicket, hierarchy)

		nameAlgSize := template.NameAlg.Size()
		if len(name) != nameAlgSize+2 {
			t.Errorf("CreatePrimary returned a name of the wrong length %d", len(name))
		}

		return objectContext, outPublic
	}

	t.Run("RSASrk", func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{uint16(128)},
						Mode:      SymModeU{SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}
		creationPCR := PCRSelectionList{
			PCRSelection{Hash: HashAlgorithmSHA1, Select: PCRSelectionData{0, 1}},
			PCRSelection{Hash: HashAlgorithmSHA256, Select: PCRSelectionData{7, 8}}}

		objectContext, pub := run(t, HandleOwner, nil, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("ECCSrk", func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeECC,
			NameAlg: HashAlgorithmSHA1,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				&ECCParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{uint16(128)},
						Mode:      SymModeU{SymModeCFB}},
					Scheme:  ECCScheme{Scheme: ECCSchemeNull},
					CurveID: ECCCurveNIST_P256,
					KDF:     KDFScheme{Scheme: KDFAlgorithmNull}}}}
		creationPCR := PCRSelectionList{
			PCRSelection{Hash: HashAlgorithmSHA1, Select: PCRSelectionData{0, 1}},
			PCRSelection{Hash: HashAlgorithmSHA256, Select: PCRSelectionData{7, 8}}}

		objectContext, pub := run(t, HandleOwner, nil, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		if len(pub.Unique.ECC().X) != 32 || len(pub.Unique.ECC().Y) != 32 {
			t.Errorf("CreatePrimary returned object with invalid ECC coords")
		}
	})

	t.Run("Ek", func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrAdminWithPolicy | AttrRestricted | AttrDecrypt,
			AuthPolicy: []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52,
				0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa},
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{uint16(128)},
						Mode:      SymModeU{SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}

		objectContext, pub := run(t, HandleEndorsement, nil, &template, Data{}, PCRSelectionList{}, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("CreateWithAuthValue", func(t *testing.T) {
		sensitive := SensitiveCreate{UserAuth: Auth(testAuth)}
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{uint16(128)},
						Mode:      SymModeU{SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}
		creationPCR := PCRSelectionList{
			PCRSelection{Hash: HashAlgorithmSHA1, Select: PCRSelectionData{0, 1}},
			PCRSelection{Hash: HashAlgorithmSHA256, Select: PCRSelectionData{7, 8}}}

		objectContext, pub := run(t, HandleOwner, &sensitive, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)

		childTemplate := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}

		_, _, _, _, _, err := tpm.Create(objectContext, nil, &childTemplate, nil, nil, testAuth)
		if err != nil {
			t.Errorf("Use of authorization on primary key failed: %v", err)
		}
	})

	t.Run("UsePasswordAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{uint16(128)},
						Mode:      SymModeU{SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}

		objectContext, pub := run(t, HandleOwner, nil, &template, Data{}, PCRSelectionList{}, testAuth)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("UseSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionContext, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		session := Session{Context: sessionContext, AuthValue: testAuth}

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{uint16(128)},
						Mode:      SymModeU{SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}

		objectContext, pub := run(t, HandleOwner, nil, &template, Data{}, PCRSelectionList{}, &session)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("WithOutsideInfo", func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{uint16(128)},
						Mode:      SymModeU{SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}
		creationPCR := PCRSelectionList{
			PCRSelection{Hash: HashAlgorithmSHA1, Select: PCRSelectionData{0, 1}},
			PCRSelection{Hash: HashAlgorithmSHA256, Select: PCRSelectionData{7, 8}}}
		data := Data("foo")

		objectContext, pub := run(t, HandleOwner, nil, &template, data, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("InvalidTemplate", func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeECC,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{uint16(128)},
						Mode:      SymModeU{SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}

		owner, _ := tpm.WrapHandle(HandleOwner)
		_, _, _, _, _, _, err := tpm.CreatePrimary(owner, nil, &template, nil, nil, nil)
		if err == nil {
			t.Fatalf("CreatePrimary should fail with an invalid template")
		}
		if err.Error() != "cannot marshal command parameters for command TPM_CC_CreatePrimary: cannot marshal struct type "+
			"tpm2.publicSized: cannot marshal field Ptr: cannot marshal sized type *tpm2.Public: cannot marshal pointer to struct to "+
			"temporary buffer: cannot marshal element: cannot marshal struct type tpm2.Public: cannot marshal field Params: cannot marshal "+
			"struct type tpm2.PublicParamsU: error marshalling union struct: data has incorrect type *tpm2.RSAParams (expected *tpm2.ECCParams)" {
			t.Errorf("CreatePrimary returned an unexpected error: %v", err)
		}
	})
}

func TestClear(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, auth interface{}) {
		var persistentObjects []HandleContext // Objects that persist across Clear
		var transientObjects []HandleContext  // Objects that are evicted by Clar

		// Create a context for a permanent resource (should persist across Clear)
		owner, _ := tpm.WrapHandle(HandleOwner)
		persistentObjects = append(persistentObjects, owner)

		// Create platform primary key (should persist across Clear)
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{uint16(128)},
						Mode:      SymModeU{SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}
		platform, _ := tpm.WrapHandle(HandlePlatform)
		platformPrimary, _, _, _, _, _, err := tpm.CreatePrimary(platform, nil, &template, nil, nil,
			nil)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		defer flushContext(t, tpm, platformPrimary)
		persistentObjects = append(persistentObjects, platformPrimary)

		// Create storage primary key (should be evicted by Clear)
		ownerPrimary := createRSASrkForTesting(t, tpm, nil)
		defer verifyContextFlushed(t, tpm, ownerPrimary)
		transientObjects = append(transientObjects, ownerPrimary)

		// Persist storage primary key (should be evicted by Clear)
		ownerPrimaryPersist := persistObjectForTesting(t, tpm, owner, ownerPrimary, Handle(0x8100ffff))
		defer verifyPersistentObjectEvicted(t, tpm, owner, ownerPrimaryPersist)
		transientObjects = append(transientObjects, ownerPrimaryPersist)

		// Persist platform primary key (should persist across Clear)
		platformPrimaryPersist := persistObjectForTesting(t, tpm, platform, platformPrimary, Handle(0x8180ffff))
		defer evictPersistentObject(t, tpm, platform, platformPrimaryPersist)
		persistentObjects = append(persistentObjects, platformPrimaryPersist)

		// Set endorsement hierarchy auth value (should be reset by Clear)
		setHierarchyAuthForTest(t, tpm, HandleEndorsement)
		defer resetHierarchyAuth(t, tpm, HandleEndorsement)

		// Create a session (should persist across Clear)
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		persistentObjects = append(persistentObjects, sessionContext)

		// Define an NV index in the owner hierarchy (should be undefined by Clear)
		nvPub1 := NVPublic{
			Index:   0x0181ffff,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
			Size:    8}
		if err := tpm.NVDefineSpace(owner, nil, &nvPub1, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		nv1, _ := tpm.WrapHandle(nvPub1.Index)
		defer verifyNVSpaceUndefined(t, tpm, nv1, owner, nil)
		transientObjects = append(transientObjects, nv1)

		// Define an NV index in the platform hierarchy (should persist across Clear)
		nvPub2 := NVPublic{
			Index:   0x0141ffff,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead|AttrNVPlatformCreate, NVTypeOrdinary),
			Size:    8}
		if err := tpm.NVDefineSpace(platform, nil, &nvPub2, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		nv2, _ := tpm.WrapHandle(nvPub2.Index)
		defer undefineNVSpace(t, tpm, nv2, platform, nil)
		persistentObjects = append(persistentObjects, nv2)

		var transientHandles []Handle
		for _, rc := range transientObjects {
			transientHandles = append(transientHandles, rc.Handle())
		}

		// Perform the clear
		lockout, _ := tpm.WrapHandle(HandleLockout)
		if err := tpm.Clear(lockout, auth); err != nil {
			t.Fatalf("Clear failed: %v", err)
		}

		// Verify that handles that should have been flushed have been
		for _, h := range transientHandles {
			handles, err := tpm.GetCapabilityHandles(h, 1)
			if err != nil {
				t.Fatalf("GetCapability failed: %v", err)
			}
			if len(handles) > 0 && handles[0] == h {
				t.Errorf("Unexpected behaviour: Handle 0x%08x should have been flushed", h)
			}
		}

		// Verify that contexts for objects that should have persisted haven't been invalidated,
		// and check that they weren't flushed from the TPM against our expectation
		for _, rc := range persistentObjects {
			if rc.Handle() == HandleNull {
				t.Fatalf("Object was evicted when it shouldn't have been")
			}
			handle := rc.Handle()
			if rc.Handle().Type() == HandleTypePolicySession {
				handle = handle&Handle(0xffffff) | HandleTypeLoadedSession.BaseHandle()
			}
			handles, err := tpm.GetCapabilityHandles(handle, 1)
			if err != nil {
				t.Fatalf("GetCapability failed: %v", err)
			}
			if len(handles) < 1 || handles[0] != rc.Handle() {
				t.Errorf("Handle 0x%08x was flushed unexpectedly", rc.Handle())
			}
		}

		// Check that the endorsement hierarchy auth has been reset
		props, err := tpm.GetCapabilityTPMProperties(PropertyPermanent, 1)
		if err != nil {
			t.Fatalf("GetCapability failed: %v", err)
		}
		if PermanentAttributes(props[0].Value)&AttrEndorsementAuthSet > 0 {
			t.Errorf("Clear did not clear the EH auth")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		run(t, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleLockout)
		defer resetHierarchyAuth(t, tpm, HandleLockout)
		run(t, testAuth)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleLockout)
		defer resetHierarchyAuth(t, tpm, HandleLockout)
		lockout, _ := tpm.WrapHandle(HandleLockout)
		sessionContext, err := tpm.StartAuthSession(nil, lockout, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, &Session{Context: sessionContext, AuthValue: testAuth})
	})
	t.Run("UseUnboundSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleLockout)
		defer resetHierarchyAuth(t, tpm, HandleLockout)
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, &Session{Context: sessionContext, AuthValue: testAuth})
	})
}

func TestHierarchyChangeAuth(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run1 := func(t *testing.T, hierarchy Handle, session interface{}) {
		h, _ := tpm.WrapHandle(hierarchy)
		if err := tpm.HierarchyChangeAuth(h, Auth(testAuth), session); err != nil {
			t.Fatalf("HierarchyChangeAuth failed: %v", err)
		}
	}

	run2 := func(t *testing.T, hierarchy Handle, session interface{},
		createPrimary func(*testing.T, *TPMContext, interface{}) HandleContext) {
		primary := createPrimary(t, tpm, session)
		flushContext(t, tpm, primary)

		h, _ := tpm.WrapHandle(hierarchy)
		if err := tpm.HierarchyChangeAuth(h, nil, session); err != nil {
			t.Errorf("HierarchyChangeAuth failed: %v", err)
		}
	}

	createSrk := func(t *testing.T, tpm *TPMContext, session interface{}) HandleContext {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{uint16(128)},
						Mode:      SymModeU{SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}
		owner, _ := tpm.WrapHandle(HandleOwner)
		objectContext, _, _, _, _, _, err := tpm.CreatePrimary(owner, nil, &template, nil, nil, session)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		return objectContext
	}
	createEk := func(t *testing.T, tpm *TPMContext, session interface{}) HandleContext {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrAdminWithPolicy | AttrRestricted | AttrDecrypt,
			AuthPolicy: []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52,
				0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa},
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   SymKeyBitsU{uint16(128)},
						Mode:      SymModeU{SymModeCFB}},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}
		endorsement, _ := tpm.WrapHandle(HandleEndorsement)
		objectContext, _, _, _, _, _, err := tpm.CreatePrimary(endorsement, nil, &template, nil, nil,
			session)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		return objectContext
	}

	t.Run("OwnerWithPW", func(t *testing.T) {
		run1(t, HandleOwner, nil)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		run2(t, HandleOwner, testAuth, createSrk)
	})

	t.Run("EndorsementWithPW", func(t *testing.T) {
		run1(t, HandleEndorsement, nil)
		defer resetHierarchyAuth(t, tpm, HandleEndorsement)

		run2(t, HandleEndorsement, testAuth, createEk)
	})

	t.Run("OwnerWithBoundHMACSession", func(t *testing.T) {
		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionContext, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, HashAlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		session := Session{Context: sessionContext, Attrs: AttrContinueSession}

		run1(t, HandleOwner, &session)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		session.AuthValue = testAuth
		run2(t, HandleOwner, &session, createSrk)
	})

	t.Run("OwnerWithUnboundHMACSession", func(t *testing.T) {
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		session := Session{Context: sessionContext, Attrs: AttrContinueSession}

		run1(t, HandleOwner, &session)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		session.AuthValue = testAuth
		run2(t, HandleOwner, &session, createSrk)
	})

	t.Run("OwnerWithUnboundHMACSession2", func(t *testing.T) {
		// This test highlights a bug where we didn't preserve the value of Session.includeAuthValue (which should be true) before computing
		// the response HMAC. It's not caught by OwnerWithUnboundHMACSession because the lack of session key combined with
		// Session.includeAuthValue incorrectly being false was causing processResponseSessionAuth to bail out early
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		session := Session{Context: sessionContext, Attrs: AttrContinueSession}

		run1(t, HandleOwner, &session)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		session.AuthValue = testAuth
		run2(t, HandleOwner, &session, createSrk)
	})
}
