package tpm2

import (
	"crypto/sha1" // #nosec G505 -- SHA-1 required for TPM event log specification
	"path/filepath"
	// #nosec G505 -- SHA-1 required for TPM event log specification compatibility
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp"
	"sort"
)

// TPM Algorithm IDs as defined in TCG specifications
const (
	AlgSHA1   uint16 = 0x0004
	AlgSHA256 uint16 = 0x000B
	AlgSHA384 uint16 = 0x000C
	AlgSHA512 uint16 = 0x000D
	AlgSM3256 uint16 = 0x0012
	// Alternative ID sometimes used for SM3_256
	AlgSM3256Alt uint16 = 0x2000
)

// Event represents a single parsed TPM event.
type Event struct {
	EventNum    int
	PCRIndex    int
	EventType   string
	DigestCount int
	Digests     []Digest
	EventSize   int
	EventString string
}

// Digest represents a single hash digest in a TPM event.
type Digest struct {
	AlgorithmId string
	Digest      string
}

// ParseEventLogOptions configures event log parsing behavior
type ParseEventLogOptions struct {
	// SkipUnknownAlgorithms allows the parser to skip digests with unknown algorithm IDs
	// instead of returning an error. Default is true for robustness.
	SkipUnknownAlgorithms bool
}

// DefaultParseEventLogOptions returns the default options for parsing event logs
func DefaultParseEventLogOptions() ParseEventLogOptions {
	return ParseEventLogOptions{
		SkipUnknownAlgorithms: true,
	}
}

// Parses the TPM event log and returns a slice of Events for each event in the log.
func ParseEventLog(filePath string) ([]Event, error) {
	return ParseEventLogWithOptions(filePath, DefaultParseEventLogOptions())
}

// ParseEventLogWithOptions parses the TPM event log with configurable options
func ParseEventLogWithOptions(filePath string, opts ParseEventLogOptions) ([]Event, error) {
	cleanPath := filepath.Clean(filePath)
	if !filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf("event log path must be absolute: %s", filePath)
	}
	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer func() { _ = file.Close() }()

	var events []Event
	eventIndex := 1

	for {
		var e Event
		e.EventNum = eventIndex
		eventIndex++

		// Read PCR index
		var pcrIndex uint32
		if err := binary.Read(file, binary.LittleEndian, &pcrIndex); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error reading PCR index: %v", err)
		}
		e.PCRIndex = int(pcrIndex)

		// Read event type
		var eventType uint32
		if err := binary.Read(file, binary.LittleEndian, &eventType); err != nil {
			return nil, fmt.Errorf("error reading event type: %v", err)
		}
		e.EventType = parseEventType(eventType)

		// Read digest count
		var digestCount uint32
		if err := binary.Read(file, binary.LittleEndian, &digestCount); err != nil {
			return nil, fmt.Errorf("error reading digest count: %v", err)
		}
		e.DigestCount = int(digestCount)

		// Parse each digest
		for i := 0; i < e.DigestCount; i++ {
			var algID uint16
			if err := binary.Read(file, binary.LittleEndian, &algID); err != nil {
				return nil, fmt.Errorf("error reading digest algorithm ID: %v", err)
			}

			// Get digest size for the algorithm
			digestSize := getDigestSizeByAlgID(algID)
			if digestSize == 0 {
				// Unknown algorithm - try to handle gracefully
				if opts.SkipUnknownAlgorithms {
					// Try to estimate digest size based on common patterns
					// or skip this digest entirely
					estimatedSize := estimateDigestSize(algID)
					if estimatedSize > 0 {
						// Skip the unknown digest bytes
						skipBytes := make([]byte, estimatedSize)
						if _, err := file.Read(skipBytes); err != nil {
							return nil, fmt.Errorf("error skipping unknown algorithm digest (0x%04x): %v", algID, err)
						}
						// Add the digest with unknown algorithm marker
						digest := Digest{
							AlgorithmId: parseAlgorithmId(algID),
							Digest:      hex.EncodeToString(skipBytes),
						}
						e.Digests = append(e.Digests, digest)
					} else {
						// Cannot determine size, this is unrecoverable for this digest
						// but we can try to continue if the event structure is valid
						return nil, fmt.Errorf("unknown algorithm ID: 0x%04x (cannot determine digest size)", algID)
					}
				} else {
					return nil, fmt.Errorf("unknown algorithm ID: 0x%04x", algID)
				}
			} else {
				digestBytes := make([]byte, digestSize)
				n, err := file.Read(digestBytes)
				if err != nil {
					return nil, fmt.Errorf("error reading digest: %v", err)
				}
				if n != digestSize {
					return nil, fmt.Errorf("error reading digest: expected %d bytes, got %d", digestSize, n)
				}
				digest := Digest{
					AlgorithmId: parseAlgorithmId(algID),
					Digest:      hex.EncodeToString(digestBytes),
				}
				e.Digests = append(e.Digests, digest)
			}
		}

		// Read event size
		var eventSize uint32
		if err := binary.Read(file, binary.LittleEndian, &eventSize); err != nil {
			return nil, fmt.Errorf("error reading event size: %v", err)
		}
		e.EventSize = int(eventSize)

		// Read event data if eventSize is greater than zero
		if eventSize > 0 {
			eventBytes := make([]byte, eventSize)
			n, err := file.Read(eventBytes)
			if err != nil {
				return nil, fmt.Errorf("error reading event data: %v", err)
			}
			if n != int(eventSize) {
				return nil, fmt.Errorf("error reading event data: expected %d bytes, got %d", eventSize, n)
			}
			e.EventString = parseEventString(eventBytes)
		}

		events = append(events, e)
	}

	return events, nil
}

// estimateDigestSize tries to estimate the digest size for unknown algorithm IDs
// based on common patterns and conventions
func estimateDigestSize(algID uint16) int {
	// Some platforms may use non-standard or vendor-specific algorithm IDs
	// Common patterns:
	// - IDs in the 0x00XX range are typically standard algorithms
	// - IDs in the 0x2XXX range may be vendor extensions
	// - IDs in the 0x6XXX range may be platform-specific
	// - IDs in the 0x7XXX range may be additional platform extensions

	// Try to guess based on common hash sizes
	switch {
	case algID >= 0x2000:
		// Any algorithm ID >= 0x2000 is likely a non-standard/vendor/platform algorithm
		// Use SHA256-sized digest (32 bytes) as a reasonable default
		return 32
	default:
		// For standard algorithm range (0x0000-0x1FFF), we should know the algorithm
		// Cannot reliably estimate if it's in the standard range but unknown
		return 0
	}
}

// getDigestSizeByAlgID returns the digest size for a given algorithm ID
func getDigestSizeByAlgID(algID uint16) int {
	switch algID {
	case AlgSHA1: // SHA-1
		return 20
	case AlgSHA256: // SHA-256
		return 32
	case AlgSHA384: // SHA-384
		return 48
	case AlgSHA512: // SHA-512
		return 64
	case AlgSM3256, AlgSM3256Alt: // SM3_256 (both standard and alternative IDs)
		return 32
	default:
		return 0
	}
}

// parseEventType translates event type codes to string representations.
func parseEventType(eventType uint32) string {
	switch eventType {
	case 0x00000000:
		return "EV_UNDEFINED"
	case 0x00000001:
		return "EV_IPL"
	case 0x00000002:
		return "EV_EVENT_TAG"
	case 0x00000003:
		return "EV_NO_ACTION"
	case 0x00000004:
		return "EV_SEPARATOR"
	case 0x00000008:
		return "EV_ACTION"
	case 0x0000000D:
		return "EV_EFI_VARIABLE_DRIVER_CONFIG"
	case 0x00000006:
		return "EV_EFI_BOOT_SERVICES_APPLICATION"
	case 0x80000001:
		return "EV_S_CRTM_CONTENTS"
	case 0x80000002:
		return "EV_S_CRTM_VERSION"
	case 0x80000003:
		return "EV_S_CPU_MICROCODE"
	case 0x80000008:
		return "EV_S_CRTM_SEPARATOR"
	case 0x80000006:
		return "EV_S_POST_CODE"
	case 0x800000E0:
		return "EV_PLATFORM_CONFIG_FLAGS"
	default:
		return fmt.Sprintf("Unknown (0x%x)", eventType)
	}
}

// parseAlgorithmId translates algorithm IDs to string representations.
func parseAlgorithmId(algID uint16) string {
	switch algID {
	case AlgSHA1:
		return "sha1"
	case AlgSHA256:
		return "sha256"
	case AlgSHA384:
		return "sha384"
	case AlgSHA512:
		return "sha512"
	case AlgSM3256, AlgSM3256Alt:
		return "sm3_256"
	default:
		return fmt.Sprintf("unknown_0x%04x", algID)
	}
}

// readDigest reads and returns a hex-encoded digest from the file.
func readDigest(file *os.File, size int) string {
	digestBytes := make([]byte, size)
	if _, err := file.Read(digestBytes); err != nil {
		return ""
	}
	return hex.EncodeToString(digestBytes)
}

// parseEventString finds the longest ASCII sequence in the event data, treating it as the primary string.
func parseEventString(data []byte) string {
	dataStr := string(data)

	// Regex to capture all printable ASCII text sequences
	re := regexp.MustCompile(`[ -~]+`)
	matches := re.FindAllString(dataStr, -1)

	// Return the longest match if available
	if len(matches) > 0 {
		longest := matches[0]
		for _, match := range matches {
			if len(match) > len(longest) {
				longest = match
			}
		}
		return longest
	}
	return ""
}

// CalculatePCRs calculates PCR values by processing each event and extending a mirror software PCR value
func CalculatePCRs(events []Event) map[string]map[int][]byte {
	pcrs := InitializePCRs()

	for _, event := range events {
		for _, digest := range event.Digests {
			// Skip unsupported algorithms (like SM3_256 which isn't in Go's standard library)
			if !isSupportedHashAlgorithm(digest.AlgorithmId) {
				continue
			}

			// Initialize PCR if it doesn't already exist
			if _, exists := pcrs[digest.AlgorithmId][event.PCRIndex]; !exists {
				pcrs[digest.AlgorithmId][event.PCRIndex] = make([]byte, GetDigestSize(digest.AlgorithmId))
			}

			// Convert the digest hex string to bytes
			digestBytes, err := hex.DecodeString(digest.Digest)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding digest: %v\n", err)
				continue
			}

			// Extend the PCR
			newPCR, err := ExtendPCR(pcrs[digest.AlgorithmId][event.PCRIndex], digestBytes, digest.AlgorithmId)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error extending PCR: %v\n", err)
				continue
			}
			pcrs[digest.AlgorithmId][event.PCRIndex] = newPCR
		}
	}

	return pcrs
}

// isSupportedHashAlgorithm checks if the algorithm is supported for PCR calculation
func isSupportedHashAlgorithm(algorithmId string) bool {
	switch algorithmId {
	case "sha1", "sha256", "sha384", "sha512":
		return true
	default:
		// SM3_256 and other algorithms are not supported for PCR calculation
		// but can still be parsed from event logs
		return false
	}
}

// InitializePCRs initializes a map to store cumulative PCR values by algorithm and index
func InitializePCRs() map[string]map[int][]byte {
	return map[string]map[int][]byte{
		"sha1":   make(map[int][]byte),
		"sha256": make(map[int][]byte),
		"sha384": make(map[int][]byte),
		"sha512": make(map[int][]byte),
	}
}

// GetHashFunction returns the hash function based on algorithm ID
func GetHashFunction(algorithmId string) (hash.Hash, error) {
	switch algorithmId {
	case "sha1":
		// #nosec G401 -- SHA-1 required for TPM event log specification compatibility
		return sha1.New(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithmId)
	}
}

// ExtendPCR extends the PCR by hashing the current PCR value and the event digest
func ExtendPCR(currentPCR []byte, digest []byte, algorithmId string) ([]byte, error) {
	hasher, err := GetHashFunction(algorithmId)
	if err != nil {
		return nil, err
	}

	// Concatenate the current PCR value with the event digest and hash the result
	hasher.Write(currentPCR)
	hasher.Write(digest)
	return hasher.Sum(nil), nil
}

// GetDigestSize returns the digest size based on the algorithm
func GetDigestSize(algorithmId string) int {
	switch algorithmId {
	case "sha1":
		return sha1.Size
	case "sha256":
		return sha256.Size
	case "sha384":
		return sha512.Size384
	case "sha512":
		return sha512.Size
	case "sm3_256":
		return 32
	default:
		return 0
	}
}

// printPCRSummary prints PCR summary with sorted indices and skips empty PCR banks
func printPCRSummary(events []Event) {
	pcrValues := CalculatePCRs(events)

	fmt.Println("pcrs:")

	for alg, pcrMap := range pcrValues {
		// Skip the algorithm if there are no PCR values
		if len(pcrMap) == 0 {
			continue
		}

		fmt.Printf("  %s:\n", alg)

		// Collect and sort PCR indices
		var indices []int
		for index := range pcrMap {
			indices = append(indices, index)
		}
		sort.Ints(indices)

		// Print each PCR index and digest with aligned colons
		for _, index := range indices {
			// Align single and double digit indices with two spaces before the colon
			fmt.Printf("    %2d : 0x%s\n", index, hex.EncodeToString(pcrMap[index]))
		}
	}
}

// PrintEvents outputs parsed events in a structured format.
func PrintEvents(events []Event) {
	for _, e := range events {
		fmt.Printf("- EventNum: %d\n", e.EventNum)
		fmt.Printf("  PCRIndex: %d\n", e.PCRIndex)
		fmt.Printf("  EventType: %s\n", e.EventType)
		fmt.Printf("  DigestCount: %d\n", e.DigestCount)
		fmt.Printf("  Digests:\n")
		for _, d := range e.Digests {
			fmt.Printf("  - AlgorithmId: %s\n", d.AlgorithmId)
			fmt.Printf("    Digest: \"%s\"\n", d.Digest)
		}
		fmt.Printf("  EventSize: %d\n", e.EventSize)
		fmt.Printf("  Event:\n    String: \"%s\"\n", e.EventString)
	}
	printPCRSummary(events)
}
