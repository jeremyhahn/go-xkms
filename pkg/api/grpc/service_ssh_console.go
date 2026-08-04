// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package grpc

import (
	"errors"
	"io"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// SSHConsole implements the bidirectional streaming SSH console over gRPC (and,
// since the unix transport registers the same service, over a Unix socket). The
// first client frame opens the PTY; subsequent frames carry stdin/resize; the
// server streams stdout and a final Exit.
func (s *Service) SSHConsole(stream pb.KeystoreService_SSHConsoleServer) error {
	if s.sshClient == nil || s.sshHostKeys == nil {
		return status.Error(codes.Unavailable, "ssh console not configured")
	}

	first, err := stream.Recv()
	if err != nil {
		return err
	}
	open := first.GetOpen()
	if open == nil {
		return status.Error(codes.InvalidArgument, "first console frame must be Open")
	}

	ctx := stream.Context()
	signer, err := s.sshClient.Keys().Signer(ctx, sdkssh.GetKeyRequest{
		Scope: open.GetScope(), Owner: open.GetOwner(), Name: open.GetKeyName(),
	})
	if err != nil {
		return sshStatus(err)
	}
	cons, err := sdkssh.OpenConsole(ctx, signer, sdkssh.ConsoleRequest{
		Host:     open.GetHost(),
		Port:     int(open.GetPort()),
		User:     open.GetUser(),
		HostKeys: s.sshHostKeys,
		Scope:    open.GetScope(),
		Owner:    open.GetOwner(),
	}, sdkssh.ConsoleConfig{
		Term: open.GetTerm(),
		Rows: int(open.GetRows()),
		Cols: int(open.GetCols()),
	})
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	defer cons.Close()

	errc := make(chan error, 2)

	// Console stdout → stream.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, rerr := cons.Read(buf)
			if n > 0 {
				out := make([]byte, n)
				copy(out, buf[:n])
				if serr := stream.Send(&pb.SSHConsoleServerMsg{
					Msg: &pb.SSHConsoleServerMsg_Stdout{Stdout: out},
				}); serr != nil {
					errc <- serr
					return
				}
			}
			if rerr != nil {
				_ = stream.Send(&pb.SSHConsoleServerMsg{
					Msg: &pb.SSHConsoleServerMsg_Exit{Exit: &pb.SSHConsoleExit{Message: rerr.Error()}},
				})
				errc <- nil
				return
			}
		}
	}()

	// Stream → console stdin / resize.
	go func() {
		for {
			msg, rerr := stream.Recv()
			if rerr != nil {
				errc <- rerr
				return
			}
			switch m := msg.GetMsg().(type) {
			case *pb.SSHConsoleClientMsg_Stdin:
				if _, werr := cons.Write(m.Stdin); werr != nil {
					errc <- werr
					return
				}
			case *pb.SSHConsoleClientMsg_Resize:
				_ = cons.Resize(int(m.Resize.GetRows()), int(m.Resize.GetCols()))
			}
		}
	}()

	err = <-errc
	if err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
