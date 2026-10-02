"""
CyberStream shared library.

Copied into every service's Docker build context (backend, generator,
streaming) as ./common, so all three import the exact same logging and
error-handling conventions rather than re-implementing them. Kept
deliberately small and dependency-free (stdlib only) so it never becomes a
version-skew problem between services.
"""
