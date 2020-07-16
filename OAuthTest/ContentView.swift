//
//  ContentView.swift
//  OAuthTest
//
//  Created by Luke Redpath on 16/07/2020.
//

import SwiftUI
import AuthenticationServices
import Combine
import CryptoKit

enum PKCE {
    static func generateCodeVerifier() -> String {
        var buffer = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)

        return base64URLEncodedString(from: Data(buffer))
    }
    
    static func generateCodeChallenge(from string: String) -> String? {
        guard let data = string.data(using: .utf8) else { return nil }
        
        let hashed = SHA256.hash(data: data)
        let stringHash = hashed.map { String(format: "%02hhx", $0) }.joined()
        
        guard let hashedData = stringHash.data(using: .utf8) else {
            return nil
        }
        
        return base64URLEncodedString(from: hashedData)
    }
    
    static func base64URLEncodedString(from data: Data) -> String {
        return data
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            .trimmingCharacters(in: .whitespaces)
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
            URLQueryItem(name: "redirect_uri", value: redirectUri)
        ]
        
        return components.url!
    }
    
    func accessTokenURL(code: String, codeVerifier: String) -> URL {
        var components = URLComponents(string: accessTokenURL.absoluteString)!
        
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "code_verifier", value: codeVerifier),
            URLQueryItem(name: "code", value: code)
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

class AuthenticationSession: ObservableObject {
    let provider: AuthenticationProvider
    let presentationContext: PresentationContext
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
    
    class PresentationContext: NSObject, ASWebAuthenticationPresentationContextProviding {
        let presentationAnchor: ASPresentationAnchor
        
        init(presentationAnchor: ASPresentationAnchor) {
            self.presentationAnchor = presentationAnchor
        }
        
        func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
            return presentationAnchor
        }
    }
    
    init(provider: AuthenticationProvider, presentationAnchor: ASPresentationAnchor) {
        self.provider = provider
        self.presentationContext = PresentationContext(presentationAnchor: presentationAnchor)
    }
    
    func start() {
        let codeVerifier = PKCE.generateCodeVerifier()
        let codeChallenge = PKCE.generateCodeChallenge(from: codeVerifier)!
        
        self.session = ASWebAuthenticationSession(
            url: self.provider.authorizeURL(codeChallenge: codeChallenge),
            callbackURLScheme: "exampleauth",
            completionHandler: { [weak self] in
                self?.handleCallback($0, $1)
            })
        self.session!.presentationContextProvider = self.presentationContext
        self.session!.start()
        
        self.state = .authenticating
        self.codeVerifier = codeVerifier
    }
    
    func cancel() {
        self.session?.cancel()
        self.state = .cancelled
    }
    
    func reset() {
        self.state = .initialized
    }
    
    private func handleCallback(_ callbackURL: URL?, _ error: Error?) {
        guard let callbackURL = callbackURL else {
            self.state = .failed
            return
        }
        
        if let error = error {
            self.state = .error(error)
            return
        }
        else {
            let queryItems = URLComponents(string: callbackURL.absoluteString)?.queryItems
            
            if let authCode = queryItems?.filter({ $0.name == "code" }).first?.value {
                self.state = .accessCodeReceived(code: authCode)
                self.obtainAccessTokenFromAccessCode(authCode)
            } else {
                self.state = .failed
            }
        }
    }
    
    private func obtainAccessTokenFromAccessCode(_ code: String) {
        var request = URLRequest(url: self.provider.accessTokenURL(code: code, codeVerifier: self.codeVerifier!))
        request.httpMethod = "POST"
        
        cancellable = URLSession.shared
            .dataTaskPublisher(for: request)
            .receive(on: DispatchQueue.main)
            .sink { _ in
                
            } receiveValue: { (data, response) in
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
            }

    }
}

struct AuthenticationView: View {
    @ObservedObject var session: AuthenticationSession
    
    init(presentationAnchor: ASPresentationAnchor) {
        self.session = AuthenticationSession(provider: .github, presentationAnchor: presentationAnchor)
    }
    
    var body: some View {
        currentStateView()
    }
    
    private func currentStateView() -> AnyView {
        switch self.session.state {
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
