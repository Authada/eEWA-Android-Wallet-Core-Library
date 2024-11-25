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

import eu.europa.ec.eudi.openid4vci.*

/**
 * Default implementation of [Offer].
 * @property issuerName issuer name
 * @property offeredDocuments offered documents
 *
 * @constructor Creates a new [DefaultOffer] instance.
 * @param credentialOffer [CredentialOffer] instance
 * @param filterConfigurations [CredentialConfigurationFilter] instance
 * @see Offer
 */
internal data class DefaultOffer(
    @JvmSynthetic val credentialOffer: CredentialOffer,
    @JvmSynthetic val filterConfigurations: List<CredentialConfigurationFilter> = listOf(
        FormatFilter,
        ProofTypeFilter
    )
) : Offer {

    override val issuerIdentifier: CredentialIssuerId
        get() = credentialOffer.credentialIssuerIdentifier

    private val issuerMetadata: CredentialIssuerMetadata
        get() = credentialOffer.credentialIssuerMetadata

    override val issuerName: String
        get() = issuerMetadata.credentialIssuerIdentifier.value.value.host

    override val offeredDocuments: List<Offer.OfferedDocument>
        get() = issuerMetadata.credentialConfigurationsSupported
            .filterKeys { it in credentialOffer.credentialConfigurationIdentifiers }
            .filterValues { conf -> filterConfigurations.all { filter -> filter(conf) } }
            .map { (id, conf) -> DefaultOfferedDocument(
                configurationIdentifier = id,
                configuration = conf
            ) }


    override val txCodeSpec: Offer.TxCodeSpec?
        get() = credentialOffer.txCodeSpec

    override fun toString(): String {
        return "Offer(issuerName='$issuerName', offeredDocuments=$offeredDocuments, txCodeSpec=$txCodeSpec)"
    }
}

/**
 * Default implementation of [Offer.OfferedDocument].
 * @property configurationIdentifier credential configuration identifier
 * @property configuration credential configuration
 * @constructor Creates a new [DefaultOfferedDocument] instance.
 * @param configurationIdentifier [CredentialConfigurationIdentifier] instance
 * @param configuration [CredentialConfiguration] instance
 */
internal data class DefaultOfferedDocument(
    @JvmSynthetic internal val configurationIdentifier: CredentialConfigurationIdentifier,
    @JvmSynthetic override val configuration: CredentialConfiguration,
) : Offer.OfferedDocument {
    override val name: String = configuration.name
    override val docType: String = configuration.docType

    /**
     *
     */
    override fun toString(): String {
        return "OfferedDocument(name='$name', docType='$docType')"
    }
}


internal val CredentialConfiguration.name: String
    @JvmSynthetic get() = display[0].name

internal val CredentialConfiguration.docType: String
    @JvmSynthetic get() = when (this) {
        is MsoMdocCredential -> docType
        is SdJwtVcCredential -> type
        is SeTlvVcCredential -> type
        else -> "unknown"
    }

internal val CredentialOffer.txCodeSpec: Offer.TxCodeSpec?
    @JvmSynthetic get() = grants?.preAuthorizedCode()?.txCode.let {
        it?.let { txCode ->
            Offer.TxCodeSpec(
                inputMode = when (txCode.inputMode) {
                    TxCodeInputMode.NUMERIC -> Offer.TxCodeSpec.InputMode.NUMERIC
                    TxCodeInputMode.TEXT -> Offer.TxCodeSpec.InputMode.TEXT
                },
                length = txCode.length,
                description = txCode.description
            )
        }
    }