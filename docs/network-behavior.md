# Network behavior

Under the validated v0.5.0-rc2 profiles, runtime inference traffic is local:

- applications connect to the Guard Proxy over loopback;
- the proxy connects to a local model server over loopback;
- the optional Open WebUI instance listens on loopback; and
- SecureInjections sends no telemetry, performs no cloud model call, follows no upstream redirect,
  and downloads no model automatically.

The Local Guard Profile and proxy configuration reject non-loopback model endpoints. The proxy
also disables environment-proxy routing for its validated upstream path.

This is not a claim that SecureInjections never uses a network. Package installation can download
Python dependencies, explicit threat-feed administration can fetch or receive artifacts through
operator-controlled workflows, and separately installed applications may have their own network
behavior. Those activities are distinct from the validated local inference path.
