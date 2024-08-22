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

package eu.europa.ec.eudi.wallet.attestation


import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.util.Base64URL
import de.authada.eewa.wallet.DeviceKeyAttestation
import de.authada.eewa.wallet.PidLib
import eu.europa.ec.eudi.wallet.issue.openid4vci.derToJose
import io.ktor.util.Hash
import org.bouncycastle.crypto.digests.SHA256Digest

class SESigner(private val pidLib: PidLib) : JWSSigner {
    override fun getJCAContext(): JCAContext = JCAContext()

    override fun supportedJWSAlgorithms(): Set<JWSAlgorithm> = setOf(JWSAlgorithm.ES256)

    override fun sign(p0: JWSHeader?, p1: ByteArray): Base64URL = Base64URL.encode(
        pidLib.signWithDevKey(p1).derToJose(JWSAlgorithm.ES256)
    )
}