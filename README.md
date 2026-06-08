# Certificate manager

This software downloads and renews application certificate.

The certificate is downloaded from CA using HTTPS. The cert-manager authenticates the first time using a token and then it uses a valid certificate to authenticate for renewal.

Each time cert-manager decides to renew the certificate, it first generate an application private key and submits a certification signing request to the configured CA. Once CA returns a new certificate the cert-manager stores certificate + private key + CA-bundle certificate (trustable CA certs) and restarts the application.

The application can be restarted by:

- sending a signal to a process specified in a PID-file
- restarting a docker container

