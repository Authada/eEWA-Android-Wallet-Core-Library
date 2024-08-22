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


import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.CNonce
import eu.europa.ec.eudi.openid4vci.ClientAttestationProvider
import eu.europa.ec.eudi.openid4vci.ClientAttestationType
import eu.europa.ec.eudi.openid4vci.ClientId
import eu.europa.ec.eudi.openid4vci.CredentialIssuerId
import eu.europa.ec.eudi.openid4vci.DefaultHttpClientFactory
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.JwtBindingKey
import eu.europa.ec.eudi.openid4vci.PopSigner
import eu.europa.ec.eudi.openid4vci.ProofTypeMeta.Jwt
import eu.europa.ec.eudi.openid4vci.ProofTypesSupported
import eu.europa.ec.eudi.wallet.EudiWallet
import eu.europa.ec.eudi.wallet.issue.openid4vci.pem
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.UUID

class WalletAttestationProvider(
    url: HttpsUrl,
    private val clock: Clock,
    private val clientId: ClientId,
    private val issuerId: CredentialIssuerId,
    private val walletProviderId: String,
    private val keyStrongBoxBacked: Boolean
) : ClientAttestationProvider {

    private val walletBackendServerClient = WalletBackendServerClient(url, DefaultHttpClientFactory)

    private fun createKeyPairWithAttestationNonce(nonce: String): KeyPair {
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
        val now = Instant.now()
        val notAfter = Date.from(now.plusSeconds(180L))
        val keySpec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAttestationChallenge(nonce.toByteArray())
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setKeyValidityEnd(notAfter)
            .setCertificateNotAfter(notAfter)
            .setIsStrongBoxBacked(keyStrongBoxBacked)
            .build()
        return with(KeyPairGenerator.getInstance("EC", "AndroidKeyStore")) {
            initialize(keySpec)
            generateKeyPair()
        }
    }


    private suspend fun createAttestation(
        signer: PopSigner.Jwt,
        type: AppAttestationType,
        attestation: String,
        cNonce: CNonce,
        seKeyAttestation: ByteArray?,
        authenticationPublicKey: PublicKey?
    ): SignedJWT {
        val proofFactory = ProofBuilder.invoke(
            ProofTypesSupported.invoke(setOf(Jwt(listOf(JWSAlgorithm.ES256)))),
            clock,
            clientId,
            walletProviderId,
            cNonce,
            signer,
            AppAttestation(type, attestation),
            seKeyAttestation,
            authenticationPublicKey
        )
        return walletBackendServerClient.placeAttestationRequest(
            WalletBackendAttestationRequest(proofFactory.build())
        ).map {
            it.attestation
        }.getOrThrow()
    }

    private fun createAttestationPop(signer: PopSigner.Jwt, aud: String, nonce: String? = null):
            SignedJWT {
        return SignedJWT(
            JWSHeader.Builder(signer.algorithm)
                .build(),
            JWTClaimsSet.Builder()
                .issuer(clientId)
                .audience(aud)
                .issueTime(
                    Date.from(clock.instant())
                )
                .jwtID(UUID.randomUUID().toString())
                .claim("nonce", nonce)
                .expirationTime(Date.from(clock.instant() + Duration.ofMinutes(1)))
                .build()
        ).apply {
            sign(signer.jwsSigner)
        }
    }

    override suspend fun getAttestation(
        nonce: String
    ): ClientAttestationType {
        val cNonceFromWalletBackend = walletBackendServerClient.getCNonce().getOrThrow().let {
            CNonce(it.cNonce, it.cNonceExpiresInSeconds)
        }
        val keyPair = createKeyPairWithAttestationNonce(cNonceFromWalletBackend.value)
        val jwk: JWK = JWK.parseFromPEMEncodedObjects(keyPair.public.pem)


        val pidLib = EudiWallet.secureElementPidLib
        val walletAttestation = pidLib?.walletAttestation(byteArrayOf(0))
        val signer = walletAttestation?.let {
            val seJwk = JWK.parseFromPEMEncodedObjects(walletAttestation.devicePublicKey.pem)
            PopSigner.Jwt(
                JWSAlgorithm.ES256,
                JwtBindingKey.Jwk(seJwk),
                SESigner(pidLib)
            )
        } ?: PopSigner.Jwt(
            JWSAlgorithm.ES256,
            JwtBindingKey.Jwk(jwk),
            ECDSASigner(keyPair.private, jwk.toECKey().curve)
        )

        val appAttestation = keyStore.getCertificateChain(KEY_ALIAS)
            .joinToString(separator = ",") { Base64URL.encode(it.encoded).toString() }

        val attestation = createAttestation(
            signer,
            AppAttestationType.Android,
            appAttestation,
            cNonceFromWalletBackend,
            walletAttestation?.keyAttestation,
            walletAttestation?.authenticationPublicKey
        )
        val attestationPop =
            createAttestationPop(signer, issuerId.value.value.toExternalForm(), nonce)
        return ClientAttestationType(
            "${attestation.serialize()}~${attestationPop.serialize()}"
        )
    }

    companion object {
        private const val KEY_ALIAS = "eu.europa.ec.eudi.wallet.WalletAttestationKey"

        private val keyStore: KeyStore
            get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }
}
