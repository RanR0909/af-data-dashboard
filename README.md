# Encrypted dashboard viewer

This public repository hosts a shared encrypted dashboard. It contains only the access page, a pinned GitHub Pages workflow, and encrypted snapshot releases. It must not contain plaintext business data, access passwords, OAuth tokens, backend sessions, or raw reports.

Open the Pages URL and enter the access password received separately from the maintainer. The password is used locally by Web Crypto; it is not sent to GitHub or written into the URL. Refreshing or closing the page locks it again.

This is a shared-password viewer, not individual account authorization. Encrypted files are public and can be downloaded. Authorized viewers can export or copy decrypted information. A password change only protects subsequent publications; previously obtained data cannot be recalled.

Data collection runs on the maintainer's configured computer, not on GitHub Pages. If that computer, a required network connection, or a source login is unavailable, the last successful publication stays online. Check source dates and synchronization status inside the unlocked dashboard.

The repository does not offer shared web uploads. The maintainer periodically imports reports and publishes a new encrypted snapshot. Browser-local changes do not update other viewers.

Snapshots use AES-256-GCM with a fresh random salt and nonce, PBKDF2-HMAC-SHA256 (600,000 iterations), and a cryptographically random 256-bit access password. The access password and collection credentials are kept off GitHub. Never replace the generated password with a short memorable password.
