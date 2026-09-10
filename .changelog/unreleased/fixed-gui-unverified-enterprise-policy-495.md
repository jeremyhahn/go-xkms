### Fixed

- The xkey GUI no longer applies a sealed enterprise policy it has not verified. Before SO login the FIDO2 authenticator and the browser-extension gates run on `DefaultPolicy()`; the file's values, including any relaxation of a secure default, apply only after the SO PIN authenticates the section. (#495)
