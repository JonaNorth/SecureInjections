# Third-party components

SecureInjections Community is prepared under Apache-2.0; historical grants remain unchanged.
The only required runtime dependency is PyYAML (MIT). The service extra adds FastAPI (MIT) and
Uvicorn (BSD-3-Clause); optional Flask is BSD-3-Clause. Their transitive dependencies retain their
own licenses in installed distribution metadata. These dependencies are installed separately,
not vendored in the Community wheel or source distribution.

Open WebUI, Ollama, and `qwen2.5:7b` are separate prerequisites used in local validation. They are
not bundled, patched, or redistributed by SecureInjections. Open WebUI 0.11.0 installed metadata
declares the Open WebUI License; operators must review its terms. Ollama and model weights retain
their respective upstream licenses and distribution terms.

Product names identify interoperability targets and do not imply endorsement. SecureInjections
does not redistribute Open WebUI files, Ollama binaries or caches, model weights, or third-party
user data.
