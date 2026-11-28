package services

import (
	"context"
	"crypto/x509"
	"testing"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// dispatchClient records which enrollment protocol the dispatch ran. The
// embedded interface is nil: any other method panics, so a test that
// reaches one fails.
type dispatchClient struct {
	ACMEClient
	calls []string
}

func (d *dispatchClient) EnrollDevice(context.Context, *sdkacme.ACMEEnrollmentConfig) (*sdkacme.ACMEEnrollmentResult, error) {
	d.calls = append(d.calls, sdkacme.ACMEChallengeTypeEnroll01)
	return &sdkacme.ACMEEnrollmentResult{
		IDevIDCertificate: &x509.Certificate{Raw: []byte{1}},
		IAKCertificate:    &x509.Certificate{Raw: []byte{2}},
	}, nil
}

func (d *dispatchClient) DeviceAttest(context.Context, *sdkacme.ACMEEnrollmentConfig) (*x509.Certificate, error) {
	d.calls = append(d.calls, sdkacme.ACMEChallengeTypeDeviceAttest01)
	return &x509.Certificate{Raw: []byte{3}}, nil
}

func (d *dispatchClient) RequestEndorsementKeyCertificate(context.Context, *sdkacme.ACMEEnrollmentConfig) (*x509.Certificate, error) {
	d.calls = append(d.calls, sdkacme.ACMEChallengeTypeEndorse01)
	return &x509.Certificate{Raw: []byte{4}}, nil
}

func TestRunACMEEnrollment_RunsSelectedChallenge(t *testing.T) {
	for _, challenge := range []string{
		sdkacme.ACMEChallengeTypeEnroll01,
		sdkacme.ACMEChallengeTypeDeviceAttest01,
		sdkacme.ACMEChallengeTypeEndorse01,
	} {
		t.Run(challenge, func(t *testing.T) {
			c := &dispatchClient{}
			res, err := RunACMEEnrollment(context.Background(), c, challenge, &sdkacme.ACMEEnrollmentConfig{})
			if err != nil {
				t.Fatalf("RunACMEEnrollment(%s): %v", challenge, err)
			}
			if res == nil || res.IDevIDCertificate == nil {
				t.Fatalf("RunACMEEnrollment(%s): no certificate in %+v", challenge, res)
			}
			if len(c.calls) != 1 || c.calls[0] != challenge {
				t.Fatalf("RunACMEEnrollment(%s) ran %v, want only %s", challenge, c.calls, challenge)
			}
		})
	}
}

func TestRunACMEEnrollment_UnknownChallengeIsAnError(t *testing.T) {
	c := &dispatchClient{}
	if _, err := RunACMEEnrollment(context.Background(), c, "http-01", &sdkacme.ACMEEnrollmentConfig{}); err == nil {
		t.Fatal("RunACMEEnrollment(http-01): want an error")
	}
	if len(c.calls) != 0 {
		t.Fatalf("unknown challenge ran %v", c.calls)
	}
}
