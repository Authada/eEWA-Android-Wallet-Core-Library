/*
 * Copyright (c) 2024 AUTHADA GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.wallet.transfer.openid4vp

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.X509CertChainUtils
import eu.europa.ec.eudi.openid4vp.X509CertificateTrust

class VerifierAttestationSignatureVerifier(private val trust: X509CertificateTrust) : JWSVerifier {

    private val defaultFactory = DefaultJWSVerifierFactory()

    override fun getJCAContext(): JCAContext = defaultFactory.jcaContext

    override fun supportedJWSAlgorithms(): MutableSet<JWSAlgorithm> =
        defaultFactory.supportedJWSAlgorithms()

    override fun verify(p0: JWSHeader?, p1: ByteArray?, p2: Base64URL?): Boolean {
        val kid = p0?.keyID
        val jwk = p0?.jwk
        val x5c = p0?.x509CertChain

        val (certChain, key) = when {
            kid == null && jwk != null && x5c.isNullOrEmpty() -> Pair(
                X509CertChainUtils.parse(jwk.x509CertChain),
                jwk
            )

            kid == null && jwk == null && !x5c.isNullOrEmpty() -> X509CertChainUtils.parse(x5c)
                .let { Pair(it, JWK.parse(it.first())) }

            kid != null && jwk == null && x5c.isNullOrEmpty() -> resolveDidUrl(kid).let {
                Pair(
                    X509CertChainUtils.parse(it.x509CertChain),
                    it
                )
            }

            else -> error("a public key must be provided in one of 'kid', 'jwk', or 'x5c'")
        }

        if (!trust.isTrusted(certChain)) {
            throw JOSEException("Untrusted")
        }
        return when (key) {
            is AsymmetricJWK -> if (
                defaultFactory.createJWSVerifier(p0, key.toPublicKey()).verify(p0, p1, p2)
            ) {
                true
            } else {
                throw JOSEException("Untrusted")
            }
            else -> throw JOSEException("Untrusted")
        }
    }
}
