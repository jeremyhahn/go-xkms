// Package loginca names the key go-qrdb signs a tenant's login certificates
// with. The xkms key reservation and the server's provisioning path share the
// name here so that it is not part of go-xkms's public API.
package loginca

// KeyCN names a tenant's login CA key: the key go-qrdb signs the tenant's
// login certificates with (Key B). The node provisions it on the backend
// directly, under this name followed by "-" and the tenant; no caller reaches
// it, or any name with that prefix, through the service.
const KeyCN = "qrdb-login-ca"
