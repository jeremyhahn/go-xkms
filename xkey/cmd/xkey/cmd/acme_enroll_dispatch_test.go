package cmd

import (
	"context"
	"crypto/x509"
	"testing"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// enrollDispatchClient records which enrollment protocol the CLI ran. The
// embedded interface is nil: any other method panics, so a test that
// reaches one fails.
type enrollDispatchClient struct {
	acmeClient
	calls []string
}

func (d *enrollDispatchClient) EnrollDevice(context.Context, *sdkacme.ACMEEnrollmentConfig) (*sdkacme.ACMEEnrollmentResult, error) {
	d.calls = append(d.calls, sdkacme.ACMEChallengeTypeEnroll01)
	return &sdkacme.ACMEEnrollmentResult{
		IDevIDCertificate: &x509.Certificate{Raw: []byte{1}},
		IAKCertificate:    &x509.Certificate{Raw: []byte{2}},
	}, nil
}

func (d *enrollDispatchClient) DeviceAttest(context.Context, *sdkacme.ACMEEnrollmentConfig) (*x509.Certificate, error) {
	d.calls = append(d.calls, sdkacme.ACMEChallengeTypeDeviceAttest01)
	return &x509.Certificate{Raw: []byte{3}}, nil
}

func (d *enrollDispatchClient) RequestEndorsementKeyCertificate(context.Context, *sdkacme.ACMEEnrollmentConfig) (*x509.Certificate, error) {
	d.calls = append(d.calls, sdkacme.ACMEChallengeTypeEndorse01)
	return &x509.Certificate{Raw: []byte{4}}, nil
}

func TestACMEEnroll_RunsSelectedChallenge(t *testing.T) {
	for _, challenge := range []string{
		sdkacme.ACMEChallengeTypeEnroll01,
		sdkacme.ACMEChallengeTypeDeviceAttest01,
		sdkacme.ACMEChallengeTypeEndorse01,
	} {
		t.Run(challenge, func(t *testing.T) {
			c := &enrollDispatchClient{}
			ef := &acmeEnrollFlags{challenge: challenge}
			res, err := ef.enroll(context.Background(), c, &sdkacme.ACMEEnrollmentConfig{})
			if err != nil {
				t.Fatalf("enroll(%s): %v", challenge, err)
			}
			if res == nil || res.IDevIDCertificate == nil {
				t.Fatalf("enroll(%s): no certificate in %+v", challenge, res)
			}
			if len(c.calls) != 1 || c.calls[0] != challenge {
				t.Fatalf("enroll(%s) ran %v, want only %s", challenge, c.calls, challenge)
			}
		})
	}
}

func TestACMEEnroll_UnknownChallengeIsAnError(t *testing.T) {
	c := &enrollDispatchClient{}
	ef := &acmeEnrollFlags{challenge: "http-01"}
	if _, err := ef.enroll(context.Background(), c, &sdkacme.ACMEEnrollmentConfig{}); err == nil {
		t.Fatal("enroll(http-01): want an error")
	}
	if len(c.calls) != 0 {
		t.Fatalf("unknown challenge ran %v", c.calls)
	}
}
