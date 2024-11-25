/*
 *  Copyright (c) 2024 AUTHADA GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package eu.europa.ec.eudi.wallet.internal

import android.util.Log
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStore
import eu.europa.ec.eudi.openid4vp.X509CertificateTrust
import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date

internal class VerifierAttestationTrust(
    private var readerTrustStore: ReaderTrustStore?
) : X509CertificateTrust {

    private var readerCertificateChain: List<X509Certificate>? = null
    private var isTrusted: Boolean? = null

    fun setReaderTrustStore(readerTrustStore: ReaderTrustStore) {
        this.readerTrustStore = readerTrustStore
        this.isTrusted = null
    }

    override fun isTrusted(chain: List<X509Certificate>): Boolean {
        readerCertificateChain = chain
        return (validateCertificationTrustPath(chain)).also {
            isTrusted = it
        }
    }

    fun getTrustResult(): Pair<List<X509Certificate>, Boolean>? =
        readerCertificateChain?.let { chain ->
            chain to (isTrusted ?: isTrusted(chain))
        }


    private fun validateCertificationTrustPath(chain: List<X509Certificate>): Boolean {
        val trustedCertificates =
            readerTrustStore?.createCertificationTrustPath(chain) ?: emptyList()

        try {
            val certStore = CertStore.getInstance(
                "Collection",
                CollectionCertStoreParameters(trustedCertificates),
            )
            val certificateFactory = CertificateFactory.getInstance("X.509")

            val certPath = certificateFactory.generateCertPath(chain)
            val trustAnchors = trustedCertificates.map { c ->
                TrustAnchor(c, null)
            }.toSet()

            val validator = CertPathValidator.getInstance("PKIX")
            val param = PKIXParameters(trustAnchors).apply {
                isRevocationEnabled = false
                addCertStore(certStore)
                date = Date()
            }

            // Path Validation
            validator.validate(certPath, param)
            return true
        } catch (e: Exception) {
            when (e) {
                is InvalidAlgorithmParameterException -> Log.d(
                    TAG,
                    "INVALID_ALGORITHM_PARAMETER",
                    e,
                )

                is NoSuchAlgorithmException -> Log.d(TAG, "NO_SUCH_ALGORITHM", e)
                is CertificateException -> Log.d(TAG, "CERTIFICATE_ERROR", e)
                is CertPathValidatorException -> Log.d(TAG, "CERTIFICATE_PATH_ERROR", e)
            }
        }

        return false
    }

    companion object {
        val TAG = this::class.qualifiedName
    }

}