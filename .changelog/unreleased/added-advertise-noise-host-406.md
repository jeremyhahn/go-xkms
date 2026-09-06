- **`cluster.raft_enrollment.advertise_noise_host` — the bind host for the
  Noise NK enrollment listener the first node of a multi-node cluster starts**
  (#406). go-qrdb#167 made `AdvertiseOptions.NoiseHost` required: that listener
  is the one socket a joining node reaches before it holds any credential, so
  clusterenroll refuses to choose a bind host, and a node contained to one
  interface must not have it quietly opened on every interface. xkms never set
  it, so multi-node first-node startup failed on the bump. The new setting is a
  bind host in the same sense as `server.host` and defaults to it; it is
  resolved once, by `Server.raftNoiseBindHost`, and reaches both the plain
  cluster path and the ACME enrollment path. It is deliberately not
  `cluster.advertise_host`, which is the address clients dial and is not a bind
  address.
