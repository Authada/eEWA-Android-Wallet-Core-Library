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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.CNonce
import eu.europa.ec.eudi.openid4vci.ClientId
import eu.europa.ec.eudi.openid4vci.JwtBindingKey
import eu.europa.ec.eudi.openid4vci.PopSigner
import eu.europa.ec.eudi.openid4vci.PopSigner.Jwt
import eu.europa.ec.eudi.openid4vci.ProofTypeMeta
import eu.europa.ec.eudi.openid4vci.ProofTypesSupported
import eu.europa.ec.eudi.wallet.attestation.AppAttestation
import java.security.PublicKey
import java.time.Clock
import java.util.Date

private interface CheckPopSigner<POP_SIGNER : PopSigner> {
    fun check(popSigner: POP_SIGNER, proofTypesSupported: ProofTypesSupported)
}

abstract class ProofBuilder<POP_SIGNER : PopSigner, out PROOF : Proof>(
    val clock: Clock,
    val iss: ClientId,
    val aud: String,
    val nonce: CNonce,
    val popSigner: POP_SIGNER,
    val attestation: AppAttestation,
    val seKeyAttestation: ByteArray? = null,
    val authenticationPublicKey: PublicKey? = null
) {

    abstract suspend fun build(): PROOF

    companion object {
        operator fun invoke(
            proofTypesSupported: ProofTypesSupported,
            clock: Clock,
            iss: ClientId,
            aud: String,
            nonce: CNonce,
            popSigner: PopSigner,
            attestation: AppAttestation,
            seKeyAttestation: ByteArray?,
            authenticationPublicKey: PublicKey?
        ): ProofBuilder<*, *> {
            return when (popSigner) {
                is Jwt -> {
                    WalletJwtProofBuilder.check(popSigner, proofTypesSupported)
                    WalletJwtProofBuilder(
                        clock = clock,
                        iss = iss,
                        aud = aud,
                        nonce = nonce,
                        popSigner = popSigner,
                        attestation = attestation,
                        seKeyAttestation = seKeyAttestation,
                        authenticationPublicKey = authenticationPublicKey
                    )
                }
            }
        }
    }
}

class WalletJwtProofBuilder(
    clock: Clock,
    iss: ClientId,
    aud: String,
    nonce: CNonce,
    popSigner: Jwt,
    attestation: AppAttestation,
    seKeyAttestation: ByteArray?,
    authenticationPublicKey: PublicKey?
) : ProofBuilder<Jwt, Proof.Jwt>(
    clock,
    iss,
    aud,
    nonce,
    popSigner,
    attestation,
    seKeyAttestation,
    authenticationPublicKey
) {
    private val headerType: String = "wallet-proof+jwt"


    override suspend fun build(): Proof.Jwt {
        val header = header()
        val claimSet = claimSet()
        val jwt = SignedJWT(header, claimSet).apply { sign(popSigner.jwsSigner) }
        return Proof.Jwt(jwt)
    }

    private fun header(): JWSHeader {
        val algorithm = popSigner.algorithm
        val headerBuilder = JWSHeader.Builder(algorithm)
        headerBuilder.type(JOSEObjectType(headerType))
        when (val key = popSigner.bindingKey) {
            is JwtBindingKey.Jwk -> headerBuilder.jwk(key.jwk.toPublicJWK())
            is JwtBindingKey.Did -> headerBuilder.keyID(key.identity)
            is JwtBindingKey.X509 -> headerBuilder.x509CertChain(key.chain.map { Base64.encode(it.encoded) })
        }
        return headerBuilder.build()
    }

    private fun claimSet(): JWTClaimsSet =
        JWTClaimsSet.Builder().apply {
            issuer(iss)
            audience(aud)
            claim("nonce", nonce.value)
            claim("app_attestation", attestation)
            seKeyAttestation?.let { claim("se_attestation", Base64.encode(seKeyAttestation).toString()) }
            authenticationPublicKey?.let {
                claim(
                    "se_authentication_key",
                    Base64.encode(authenticationPublicKey.encoded).toString()
                )
            }
            issueTime(Date.from(clock.instant()))
        }.build()


    companion object : CheckPopSigner<Jwt> {

        override fun check(popSigner: Jwt, proofTypesSupported: ProofTypesSupported) {
            val spec =
                proofTypesSupported.values.filterIsInstance<ProofTypeMeta.Jwt>().firstOrNull()
                    ?: throw IllegalArgumentException("Unsupported proof type")
            val proofTypeSigningAlgorithmsSupported = spec.algorithms
            if (popSigner.algorithm !in proofTypeSigningAlgorithmsSupported) {
                throw IllegalArgumentException("Unsupported proof algorithm")
            }
        }
    }
}
