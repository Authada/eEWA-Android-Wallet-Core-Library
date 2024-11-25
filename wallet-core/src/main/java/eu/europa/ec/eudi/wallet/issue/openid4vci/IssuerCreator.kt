/*
 * Copyright (c) 2024 European Commission
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
 *
 * Modified by AUTHADA GmbH
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

package eu.europa.ec.eudi.wallet.issue.openid4vci

import android.content.Context
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.CredentialIssuerId
import eu.europa.ec.eudi.openid4vci.CredentialResponseEncryptionPolicy
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.Issuer
import eu.europa.ec.eudi.openid4vci.KeyGenerationConfig
import eu.europa.ec.eudi.openid4vci.OpenId4VCIConfig
import eu.europa.ec.eudi.openid4vci.internal.VerifierKA
import eu.europa.ec.eudi.wallet.attestation.WalletAttestationProvider
import eu.europa.ec.eudi.wallet.document.internal.supportsStrongBox
import java.net.URI
import java.time.Clock

internal class IssuerCreator {
    /**
     * Creates an [Issuer] from the given [Offer].
     * @param offer The [Offer].
     * @return The [Issuer].
     */
    fun createIssuer(offer: Offer, config: OpenId4VciManager.Config, context: Context, keyForIssuingAuthChannel: JWK?, issuerIdentifier: CredentialIssuerId): Issuer {
        val credentialOffer = (offer as DefaultOffer).credentialOffer
        return Issuer.make(config.toOpenId4VCIConfig(
            context = context,
            keyForIssuingAuthChannel = keyForIssuingAuthChannel,
            issuerIdentifier = issuerIdentifier
        ), credentialOffer)
            .getOrThrow()
    }


    private fun OpenId4VciManager.Config.toOpenId4VCIConfig(
        context: Context,
        keyForIssuingAuthChannel: JWK?,
        issuerIdentifier: CredentialIssuerId
    ): OpenId4VCIConfig {
        val keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048)
        val attestationKeyHardwareBacked =
            this.useStrongBoxIfSupported && context.supportsStrongBox
        return OpenId4VCIConfig(
            clientId = clientId,
            authFlowRedirectionURI = URI.create(authFlowRedirectionURI),
            keyGenerationConfig = keyGenerationConfig,
            credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
            dPoPSigner = if (useDPoPIfSupported) DPoPSigner().toPopSigner() else null,
            clientAttestationProvider = this.walletProviderUrl?.let {
                WalletAttestationProvider(
                    url = HttpsUrl(it).getOrThrow(),
                    clock = Clock.systemUTC(),
                    clientId = clientId,
                    issuerId = issuerIdentifier,
                    walletProviderId = it,
                    keyStrongBoxBacked = attestationKeyHardwareBacked
                )
            },
            verifierKA = keyForIssuingAuthChannel?.let {
                VerifierKA(keyForIssuingAuthChannel)
            }
        )
    }
}