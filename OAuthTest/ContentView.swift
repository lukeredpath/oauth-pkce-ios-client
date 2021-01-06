//
//  ContentView.swift
//  OAuthTest
//
//  Created by Luke Redpath on 16/07/2020.
//

import AuthenticationServices
import Combine
import CryptoKit
import SwiftUI

extension Data {
    // Returns a base64 encoded string, replacing reserved characters
    // as per the PKCE spec https://tools.ietf.org/html/rfc7636#section-4.2
    func pkce_base64EncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            .trimmingCharacters(in: .whitespaces)
    }
}

enum PKCE {
    static func generateCodeVerifier() -> String {
        var buffer = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
        return Data(buffer).base64EncodedString()
    }

    static func generateCodeChallenge(from string: String) -> String? {
        guard let data = string.data(using: .utf8) else { return nil }
        let hashed = SHA256.hash(data: data)
        return Data(hashed).pkce_base64EncodedString()
    }
}

struct AuthenticationProvider {
    private let authorizeBaseURL: URL
    private let accessTokenURL: URL
    private let clientId: String
    private let redirectUri: String

    func authorizeURL(codeChallenge: String) -> URL {
        var components = URLComponents(string: authorizeBaseURL.absoluteString)!

        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
        ]

        return components.url!
    }

    func accessTokenURL(code: String, codeVerifier: String) -> URL {
        var components = URLComponents(string: accessTokenURL.absoluteString)!

        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "code_verifier", value: codeVerifier),
            URLQueryItem(name: "code", value: code),
        ]

        return components.url!
    }
}

struct AccessToken: Equatable {
    var token: String
    var scope: String?
    var type: String?
}

extension AuthenticationProvider {
    static let github = AuthenticationProvider(
        authorizeBaseURL: URL(string: "http://localhost:9292/oauth/authorize")!,
        accessTokenURL: URL(string: "http://localhost:9292/oauth/access_token")!,
        clientId: "a7b6cf3eb12c349626d6",
        redirectUri: "exampleauth://github/code"
    )
}

class AuthenticationSession: NSObject, ObservableObject, ASWebAuthenticationPresentationContextProviding {
    let provider: AuthenticationProvider
    let presentationAnchor: ASPresentationAnchor
    var session: ASWebAuthenticationSession?
    var codeVerifier: String?
    var cancellable: AnyCancellable?

    @Published var state: State = .initialized

    enum State {
        case initialized
        case authenticating
        case accessCodeReceived(code: String)
        case authenticated(accessToken: AccessToken)
        case error(Error)
        case failed
        case cancelled
    }

    init(provider: AuthenticationProvider, presentationAnchor: ASPresentationAnchor) {
        self.provider = provider
        self.presentationAnchor = presentationAnchor
    }

    func presentationAnchor(for _: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return presentationAnchor
    }

    func start() {
        let codeVerifier = PKCE.generateCodeVerifier()

        session = ASWebAuthenticationSession(
            url: provider.authorizeURL(
                codeChallenge: PKCE.generateCodeChallenge(from: codeVerifier)!
            ),
            callbackURLScheme: "exampleauth",
            completionHandler: { [weak self] in
                self?.handleCallback($0, $1)
            }
        )
        session!.presentationContextProvider = self
        session!.start()

        state = .authenticating
        self.codeVerifier = codeVerifier
    }

    func cancel() {
        session?.cancel()
        state = .cancelled
    }

    func reset() {
        state = .initialized
    }

    private func handleCallback(_ callbackURL: URL?, _ error: Error?) {
        guard let callbackURL = callbackURL else {
            state = .failed
            return
        }

        if let error = error {
            state = .error(error)
            return
        } else {
            let queryItems = URLComponents(string: callbackURL.absoluteString)?.queryItems

            if let authCode = queryItems?.filter({ $0.name == "code" }).first?.value {
                state = .accessCodeReceived(code: authCode)
                obtainAccessTokenFromAccessCode(authCode)
            } else {
                state = .failed
            }
        }
    }

    private func obtainAccessTokenFromAccessCode(_ code: String) {
        var request = URLRequest(url: provider.accessTokenURL(code: code, codeVerifier: codeVerifier!))
        request.httpMethod = "POST"

        cancellable = URLSession.shared
            .dataTaskPublisher(for: request)
            .receive(on: DispatchQueue.main)
            .sink { _ in

            } receiveValue: { data, response in
                guard let response = response as? HTTPURLResponse else {
                    self.state = .failed
                    return
                }
                guard let body = String(data: data, encoding: .utf8), response.statusCode == 200 else {
                    self.state = .failed
                    return
                }
                let parameters: [String: String] = body.components(separatedBy: "&").reduce(into: [:]) { dict, pairString in
                    let keyValue = pairString.components(separatedBy: "=")
                    dict[keyValue.first!] = keyValue.last!
                }
                let token = AccessToken(
                    token: parameters["access_token"]!,
                    scope: parameters["scope"],
                    type: parameters["bearer"]
                )
                self.state = .authenticated(accessToken: token)
                self.codeVerifier = nil
            }
    }
}

struct AuthenticationView: View {
    @ObservedObject var session: AuthenticationSession

    init(presentationAnchor: ASPresentationAnchor) {
        session = AuthenticationSession(provider: .github, presentationAnchor: presentationAnchor)
    }

    var body: some View {
        currentStateView()
    }

    private func currentStateView() -> AnyView {
        switch session.state {
        case .initialized:
            return AnyView(Button("Authenticate now") {
                self.session.start()
            })
        case .authenticating:
            return AnyView(Text("Authenticating..."))
        case .accessCodeReceived:
            return AnyView(Text("Exchanging code for access token..."))
        case let .authenticated(accessToken):
            return AnyView(VStack {
                Text("Authenticated")
                Text(accessToken.token)
            }.padding())
        case .failed:
            return AnyView(authenticationEnded("Authentication failed"))
        case .error:
            return AnyView(authenticationEnded("Authentication error"))
        case .cancelled:
            return AnyView(authenticationEnded("Authentication cancelled"))
        }
    }

    private func authenticationEnded(_ message: String) -> some View {
        VStack {
            Text(message)
            Button("Reset") {
                self.session.reset()
            }
        }
    }
}

struct ContentView: View {
    @State var currentWindow: UIWindow?

    var body: some View {
        Group {
            if let window = currentWindow {
                AuthenticationView(presentationAnchor: window)
            }
        }
        .onAppear {
            self.currentWindow = UIApplication.shared.windows.first
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
