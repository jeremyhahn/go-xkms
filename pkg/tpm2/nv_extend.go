package tpm2

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	// tpmSTSessions is TPM_ST_SESSIONS: the command or response carries an
	// authorization area.
	tpmSTSessions = uint16(0x8002)

	// tpmSTNoSessions is TPM_ST_NO_SESSIONS: the response carries no
	// authorization area.
	tpmSTNoSessions = uint16(0x8001)

	// tpmHeaderSize is the size of a command or response header: tag (2),
	// size (4) and command or response code (4).
	tpmHeaderSize = 10
)

// nvExtendExecute executes TPM2_NV_Extend (TCG TPM 2.0 Part 3, section
// 31.9), which go-tpm does not implement, extending data into nvIndex under
// the authorization authHandle carries.
//
// The command is marshalled here, but its authorization is computed by the
// go-tpm Session in authHandle.Auth -- Session.Authorize over the command's
// cpHash and Session.Validate over the response's rpHash -- so an HMAC
// session authorizes it exactly as it would any go-tpm command, and a salted
// one keeps the auth value off the bus. authHandle.Name may be empty for a
// permanent handle such as a hierarchy, whose Name is the handle itself.
func nvExtendExecute(
	t transport.TPM,
	authHandle tpm2.AuthHandle,
	nvIndex tpm2.NamedHandle,
	data []byte) error {

	session := authHandle.Auth
	if err := session.Init(t); err != nil {
		return &errs.Wrapped{Msg: "NV_Extend: initialize session", Err: err}
	}
	if err := session.NewNonceCaller(); err != nil {
		return &errs.Wrapped{Msg: "NV_Extend: nonceCaller", Err: err}
	}

	authName := authHandle.Name
	if len(authName.Buffer) == 0 {
		authName = tpm2.HandleName(authHandle.Handle)
	}
	names := []tpm2.TPM2BName{authName, nvIndex.Name}
	parms := tpm2.Marshal(tpm2.TPM2BMaxNVBuffer{Buffer: data})

	authCmd, err := session.Authorize(tpm2.TPMCCNVExtend, parms, nil, names, 0)
	if err != nil {
		return &errs.Wrapped{Msg: "NV_Extend: authorize", Err: err}
	}
	authArea := tpm2.Marshal(*authCmd)

	// Header, handles, authorization area size and area, parameters.
	totalSize := tpmHeaderSize + 8 + 4 + len(authArea) + len(parms)
	cmd := make([]byte, 0, totalSize)
	cmd = binary.BigEndian.AppendUint16(cmd, tpmSTSessions)
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(totalSize)) // #nosec G115 -- bounded by TPM2B sizes
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(tpm2.TPMCCNVExtend))
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(authHandle.Handle))
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(nvIndex.Handle))
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(len(authArea))) // #nosec G115 -- one TPMS_AUTH_COMMAND
	cmd = append(cmd, authArea...)
	cmd = append(cmd, parms...)

	rsp, err := t.Send(cmd)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to send NV_Extend command", Err: err}
	}

	if len(rsp) < tpmHeaderSize {
		return &errs.Message{Msg: fmt.Sprintf("response too short: %d bytes", len(rsp))}
	}
	respTag := binary.BigEndian.Uint16(rsp[0:2])
	if respTag != tpmSTSessions && respTag != tpmSTNoSessions {
		return &errs.Message{Msg: fmt.Sprintf("unexpected response tag: 0x%04x", respTag)}
	}
	respSize := binary.BigEndian.Uint32(rsp[2:6])
	if uint32(len(rsp)) < respSize {
		return &errs.Message{Msg: fmt.Sprintf("response truncated: got %d, expected %d", len(rsp), respSize)}
	}
	if respCode := binary.BigEndian.Uint32(rsp[6:10]); respCode != 0 {
		rc := tpm2.TPMRC(respCode)
		if cleanupErr := session.CleanupFailure(t); cleanupErr != nil {
			return &errs.Joined{Lead: rc, Detail: "session cleanup", Cause: cleanupErr}
		}
		return rc
	}

	// A successful response with sessions carries the parameter area size
	// (NV_Extend returns no parameters) followed by one TPMS_AUTH_RESPONSE,
	// which the session validates.
	body := bytes.NewBuffer(rsp[tpmHeaderSize:respSize])
	var parmsSize uint32
	if err := binary.Read(body, binary.BigEndian, &parmsSize); err != nil {
		return &errs.Wrapped{Msg: "NV_Extend: response parameter size", Err: err}
	}
	if int(parmsSize) > body.Len() {
		return &errs.Message{Msg: fmt.Sprintf("NV_Extend: response parameter size %d exceeds response", parmsSize)}
	}
	rspParms := body.Next(int(parmsSize))
	authRsp, err := tpm2.Unmarshal[tpm2.TPMSAuthResponse](body.Bytes())
	if err != nil {
		return &errs.Wrapped{Msg: "NV_Extend: response authorization", Err: err}
	}
	if err := session.Validate(tpm2.TPMRCSuccess, tpm2.TPMCCNVExtend, rspParms, names, 0, authRsp); err != nil {
		return &errs.Wrapped{Msg: "NV_Extend: validate response authorization", Err: err}
	}
	return nil
}
