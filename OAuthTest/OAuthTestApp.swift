//
//  OAuthTestApp.swift
//  OAuthTest
//
//  Created by Luke Redpath on 16/07/2020.
//

import SwiftUI

struct WindowEnvironmentKey: EnvironmentKey {
    static let defaultValue: UIWindow? = nil
}

extension EnvironmentValues {
    var window: UIWindow? {
        get { self[WindowEnvironmentKey] }
        set { self[WindowEnvironmentKey] = newValue }
    }
}

@main
struct OAuthTestApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
