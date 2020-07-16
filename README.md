# iOS OAuth with PKCE example client

This is a very small SwiftUI app that demonstrates how to authenticate using OAuth using the authorization code grant with PKCE.

It is designed to work with the [proof-of-concept PKCE proxy server](https://github.com/lukeredpath/oauth-pkce-proxy).

The example app does not use any third-party libraries. It:

* Uses `ASWebAuthenticationSession` from the `AuthenticationServices` framework to allow the user to authenticate with a third-party service via the PKCE proxy and obtain the authorization grant code.
* Uses `CryptoKit` to generate the PKCE code challenge.
* Makes a simple POST request using `URLSession` to exchange the authentication code for an access token, again via the PKCE proxy.

This is not production-ready code and is simply a proof of concept.
