//
//  ViewController.swift
//  OpenSSLProject
//
//  Copyright © 2023 SAP SE or an SAP affiliate company. All rights reserved.
//
//  No part of this publication may be reproduced or transmitted in any form or for any purpose
//  without the express permission of SAP SE. The information contained herein may be changed
//  without prior notice.
//

import UIKit
import Foundation

class ViewController: UIViewController {

    let fileName = "MAFTEST"
    let fileType = "p12"
    let passphrase = "Mobile123"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        checkTheAppleAPI()
    }


    func checkTheAppleAPI() {
        obtainUserIdentity { data, error in
            if let pkcs12Data = data {
                let query = [kSecImportExportPassphrase as String: ""]
                var items: CFArray?
                let err = SecPKCS12Import(pkcs12Data as CFData, query as CFDictionary, &items)
                print("error in:: SecPKCS12Import", err.error, "\n", err)
            }
        }
    }
    
    public func obtainUserIdentity(completionHandler: @escaping (Data?, Error?) -> Void) {
        guard let path = Bundle.main.path(forResource: fileName, ofType: fileType) else {
            return
        }
        let fileURL = URL(fileURLWithPath: path)
        var data: Data!
        do {
            let dataOpt = try Data(contentsOf: fileURL)
            data = dataOpt
        } catch {
            print(" error while ", error)
            return
        }
       
        guard let pkcs12Data = OpenSSLHelperProxy.shared.createPKCS12fromPKCS12Data(data, passphraseOriginal: passphrase, passphraseNew: "") else {
            completionHandler(nil, nil)
            return
        }
        completionHandler(pkcs12Data, nil)
    }
}

extension OSStatus {

    var error: NSError? {
        guard self != errSecSuccess else { return nil }

        let message = SecCopyErrorMessageString(self, nil) as String? ?? "Unknown error"

        return NSError(domain: NSOSStatusErrorDomain, code: Int(self), userInfo: [
            NSLocalizedDescriptionKey: message])
    }
}
