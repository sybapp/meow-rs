// Test-only independent VLESS decoder. Handles the fixture's plain TCP request;
// protocol/runtime code never imports this. UUID and target are synthetic.
package main

import (
	"fmt"
	"io"
	"net"
)

func vlessFixture(conn net.Conn) error {
	var fixed [18]byte
	if _, err := io.ReadFull(conn, fixed[:]); err != nil {
		return err
	}
	if fixed[0] != 0 {
		return fmt.Errorf("VLESS fixture version %d", fixed[0])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(fixed[17])); err != nil {
		return err
	}
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return err
	}
	if request[0] != 1 || request[1] != 1 || request[2] != 187 || request[3] != 2 {
		return fmt.Errorf("unexpected VLESS fixture command/port/address type: %v", request)
	}
	var length [1]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return err
	}
	name := make([]byte, int(length[0]))
	if _, err := io.ReadFull(conn, name); err != nil {
		return err
	}
	if string(name) != "target.example" {
		return fmt.Errorf("unexpected VLESS destination")
	}
	_, err := conn.Write([]byte{0, 0})
	return err
}
