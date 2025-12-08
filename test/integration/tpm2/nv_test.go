//go:build integration

package integration

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TestIntegration_NVDefineAndDelete tests NV index definition and deletion
func TestIntegration_NVDefineAndDelete(t *testing.T) {
	conn := openTPM(t)
	defer conn.Close()

	tpmTransport := transport.FromReadWriter(conn)
	executeTPMStartup(t, tpmTransport)

	// Use a test NV index in the user-defined range
	nvIndex := tpm2.TPMHandle(0x01500100)
	dataSize := uint16(32)

	// Define NV space
	defineSpace := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: nvIndex,
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
				},
				DataSize: dataSize,
			}),
	}

	_, err := defineSpace.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}

	t.Logf("Successfully defined NV index 0x%x with size %d", nvIndex, dataSize)

	// Verify NV index was created by reading its public area
	readPub := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	pubRsp, err := readPub.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVReadPublic failed: %v", err)
	}

	nvPub, err := pubRsp.NVPublic.Contents()
	if err != nil {
		t.Fatalf("Failed to get NV public contents: %v", err)
	}

	if nvPub.NVIndex != nvIndex {
		t.Errorf("NV index mismatch: got 0x%x, want 0x%x", nvPub.NVIndex, nvIndex)
	}

	if nvPub.DataSize != dataSize {
		t.Errorf("NV data size mismatch: got %d, want %d", nvPub.DataSize, dataSize)
	}

	t.Logf("Verified NV index 0x%x exists", nvIndex)

	// Delete NV space
	undefineSpace := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: nvIndex,
			Name:   pubRsp.NVName,
			Auth:   tpm2.PasswordAuth(nil),
		},
	}

	_, err = undefineSpace.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVUndefineSpace failed: %v", err)
	}

	t.Logf("Successfully deleted NV index 0x%x", nvIndex)
}

// TestIntegration_NVWriteAndRead tests writing and reading NV data
func TestIntegration_NVWriteAndRead(t *testing.T) {
	conn := openTPM(t)
	defer conn.Close()

	tpmTransport := transport.FromReadWriter(conn)
	executeTPMStartup(t, tpmTransport)

	nvIndex := tpm2.TPMHandle(0x01500101)
	testData := []byte("This is test data for NV")
	dataSize := uint16(len(testData))

	// Define NV space
	defineSpace := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: nvIndex,
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
				},
				DataSize: dataSize,
			}),
	}

	_, err := defineSpace.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer func() {
		// Cleanup
		readPub := tpm2.NVReadPublic{NVIndex: nvIndex}
		pubRsp, _ := readPub.Execute(tpmTransport)
		if pubRsp != nil {
			undefine := tpm2.NVUndefineSpace{
				AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
				NVIndex:    tpm2.AuthHandle{Handle: nvIndex, Name: pubRsp.NVName, Auth: tpm2.PasswordAuth(nil)},
			}
			undefine.Execute(tpmTransport)
		}
	}()

	t.Logf("Defined NV index 0x%x", nvIndex)

	// Write data
	readPub := tpm2.NVReadPublic{NVIndex: nvIndex}
	pubRsp, err := readPub.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVReadPublic failed: %v", err)
	}

	nvWrite := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: nvIndex,
			Name:   pubRsp.NVName,
		},
		Data:   tpm2.TPM2BMaxNVBuffer{Buffer: testData},
		Offset: 0,
	}

	_, err = nvWrite.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVWrite failed: %v", err)
	}

	t.Logf("Wrote %d bytes to NV index", len(testData))

	// Read data back
	nvRead := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: nvIndex,
			Name:   pubRsp.NVName,
		},
		Size:   dataSize,
		Offset: 0,
	}

	readRsp, err := nvRead.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVRead failed: %v", err)
	}

	if !bytes.Equal(readRsp.Data.Buffer, testData) {
		t.Errorf("Data mismatch: got %v, want %v", readRsp.Data.Buffer, testData)
	}

	t.Logf("Successfully read back data from NV index")
}

// TestIntegration_NVLargeData tests NV operations with larger data
func TestIntegration_NVLargeData(t *testing.T) {
	conn := openTPM(t)
	defer conn.Close()

	tpmTransport := transport.FromReadWriter(conn)
	executeTPMStartup(t, tpmTransport)

	nvIndex := tpm2.TPMHandle(0x01500102)
	// Create larger test data (256 bytes)
	testData := make([]byte, 256)
	for i := range testData {
		testData[i] = byte(i)
	}
	dataSize := uint16(len(testData))

	// Define NV space
	defineSpace := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: nvIndex,
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
				},
				DataSize: dataSize,
			}),
	}

	_, err := defineSpace.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer func() {
		readPub := tpm2.NVReadPublic{NVIndex: nvIndex}
		pubRsp, _ := readPub.Execute(tpmTransport)
		if pubRsp != nil {
			undefine := tpm2.NVUndefineSpace{
				AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
				NVIndex:    tpm2.AuthHandle{Handle: nvIndex, Name: pubRsp.NVName, Auth: tpm2.PasswordAuth(nil)},
			}
			undefine.Execute(tpmTransport)
		}
	}()

	// Get NV name
	readPub := tpm2.NVReadPublic{NVIndex: nvIndex}
	pubRsp, err := readPub.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVReadPublic failed: %v", err)
	}

	// Write large data
	nvWrite := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: nvIndex,
			Name:   pubRsp.NVName,
		},
		Data:   tpm2.TPM2BMaxNVBuffer{Buffer: testData},
		Offset: 0,
	}

	_, err = nvWrite.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVWrite failed: %v", err)
	}

	t.Logf("Wrote %d bytes to NV", len(testData))

	// Read back
	nvRead := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: nvIndex,
			Name:   pubRsp.NVName,
		},
		Size:   dataSize,
		Offset: 0,
	}

	readRsp, err := nvRead.Execute(tpmTransport)
	if err != nil {
		t.Fatalf("NVRead failed: %v", err)
	}

	if !bytes.Equal(readRsp.Data.Buffer, testData) {
		t.Errorf("Large data mismatch")
	}

	t.Logf("Successfully verified %d bytes of NV data", len(testData))
}

// TestIntegration_NVErrorConditions tests error handling in NV operations
func TestIntegration_NVErrorConditions(t *testing.T) {
	conn := openTPM(t)
	defer conn.Close()

	tpmTransport := transport.FromReadWriter(conn)
	executeTPMStartup(t, tpmTransport)

	t.Run("ReadNonExistentIndex", func(t *testing.T) {
		// Try to read a non-existent NV index
		nvIndex := tpm2.TPMHandle(0x01500999)
		readPub := tpm2.NVReadPublic{NVIndex: nvIndex}
		_, err := readPub.Execute(tpmTransport)
		if err == nil {
			t.Error("Expected error when reading non-existent NV index")
		}
		t.Logf("Got expected error for non-existent index: %v", err)
	})

	t.Run("WriteWithWrongAuth", func(t *testing.T) {
		nvIndex := tpm2.TPMHandle(0x01500103)
		dataSize := uint16(32)

		// Define with password
		nvPassword := []byte("secret123")
		defineSpace := tpm2.NVDefineSpace{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(nil),
			},
			Auth: tpm2.TPM2BAuth{Buffer: nvPassword},
			PublicInfo: tpm2.New2B(
				tpm2.TPMSNVPublic{
					NVIndex: nvIndex,
					NameAlg: tpm2.TPMAlgSHA256,
					Attributes: tpm2.TPMANV{
						AuthRead:  true,
						AuthWrite: true,
						NT:        tpm2.TPMNTOrdinary,
						NoDA:      true,
					},
					DataSize: dataSize,
				}),
		}

		_, err := defineSpace.Execute(tpmTransport)
		if err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		defer func() {
			readPub := tpm2.NVReadPublic{NVIndex: nvIndex}
			pubRsp, _ := readPub.Execute(tpmTransport)
			if pubRsp != nil {
				undefine := tpm2.NVUndefineSpace{
					AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
					NVIndex:    tpm2.AuthHandle{Handle: nvIndex, Name: pubRsp.NVName, Auth: tpm2.PasswordAuth(nil)},
				}
				undefine.Execute(tpmTransport)
			}
		}()

		// Try to write with wrong password
		readPub := tpm2.NVReadPublic{NVIndex: nvIndex}
		pubRsp, _ := readPub.Execute(tpmTransport)

		nvWrite := tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{
				Handle: nvIndex,
				Name:   pubRsp.NVName,
				Auth:   tpm2.PasswordAuth([]byte("wrongpassword")),
			},
			NVIndex: tpm2.AuthHandle{
				Handle: nvIndex,
				Name:   pubRsp.NVName,
			},
			Data:   tpm2.TPM2BMaxNVBuffer{Buffer: []byte("test")},
			Offset: 0,
		}

		_, err = nvWrite.Execute(tpmTransport)
		if err == nil {
			t.Error("Expected auth error with wrong password")
		}
		t.Logf("Got expected auth error: %v", err)
	})
}
