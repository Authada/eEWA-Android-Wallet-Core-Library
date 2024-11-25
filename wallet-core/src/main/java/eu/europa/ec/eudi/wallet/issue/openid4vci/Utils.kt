/*
 *  Copyright (c) 2024 European Commission
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
 *
 *  Modified by AUTHADA GmbH
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

package eu.europa.ec.eudi.wallet.issue.openid4vci

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.impl.ECDSA
import eu.europa.ec.eudi.openid4vci.CredentialConfiguration
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError
import eu.europa.ec.eudi.openid4vci.Display
import eu.europa.ec.eudi.openid4vci.MsoMdocCredential
import eu.europa.ec.eudi.openid4vci.ProofTypeMeta
import eu.europa.ec.eudi.openid4vci.SdJwtVcCredential
import eu.europa.ec.eudi.openid4vci.SeTlvVcCredential
import eu.europa.ec.eudi.openid4vci.type
import eu.europa.ec.eudi.wallet.document.CreateIssuanceRequestResult
import eu.europa.ec.eudi.wallet.document.DocumentId
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.Format
import eu.europa.ec.eudi.wallet.document.IssuanceRequest
import eu.europa.ec.eudi.wallet.document.room.DocumentMetaData
import eu.europa.ec.eudi.wallet.document.room.DocumentMetaData.Image
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.StringWriter
import java.security.PublicKey

internal fun interface CredentialConfigurationFilter {
    operator fun invoke(conf: CredentialConfiguration): Boolean
}

@JvmSynthetic
internal val FormatFilter: CredentialConfigurationFilter = CredentialConfigurationFilter { conf ->
    conf is MsoMdocCredential || conf is SdJwtVcCredential
}

@JvmSynthetic
internal val ProofTypeFilter: CredentialConfigurationFilter =
    CredentialConfigurationFilter { conf ->
        conf.proofTypesSupported.values.map {
            it.type()
        }.firstOrNull { it in ProofSigner.SupportedProofTypes.keys }
            ?.let { proofType ->
                conf.proofTypesSupported[proofType]
                    ?.let { metadata ->
                        ProofSigner.SupportedProofTypes[proofType]?.let { proofSignerAlg ->
                            when (metadata) {
                                is ProofTypeMeta.Jwt -> {
                                    metadata.algorithms.any { it in proofSignerAlg }
                                }

                                ProofTypeMeta.Cwt -> true
                                ProofTypeMeta.LdpVp -> true
                            }
                        } ?: false
                    } ?: false
            } ?: false
    }

internal class DocTypeFilterFactory(
    private val docType: String,
    private val supportedFormats: Set<CredentialFormat>
) : CredentialConfigurationFilter {
    override fun invoke(conf: CredentialConfiguration): Boolean =
        supportedFormats.any { it.clazz.isInstance(conf) } && conf.docType == docType
}

internal val CreateIssuanceRequestResult.result: Result<IssuanceRequest>
    @JvmSynthetic get() = when (this) {
        is CreateIssuanceRequestResult.Success -> Result.success(issuanceRequest)
        is CreateIssuanceRequestResult.Failure -> Result.failure(throwable)
    }

@JvmSynthetic
internal fun DocumentManager.createIssuanceRequest(
    offerOfferedDocument: Offer.OfferedDocument,
    hardwareBacked: Boolean = true,
    storeDocument: Boolean = true
): Result<IssuanceRequest> =
    createIssuanceRequest(
        docType = offerOfferedDocument.docType,
        format = when (offerOfferedDocument.configuration) {
            is MsoMdocCredential -> Format.MSO_MDOC
            is SdJwtVcCredential -> Format.SD_JWT_VC
            is SeTlvVcCredential -> Format.SE_TLV
            else -> throw CredentialIssuanceError.UnsupportedCredentialFormat
        },
        hardwareBacked = hardwareBacked,
        storeDocument = storeDocument
    )
        .result
        .map { it.apply { name = offerOfferedDocument.name } }

internal val PublicKey.pem: String
    @JvmSynthetic get() = StringWriter().use { wr ->
        PemWriter(wr).use { pwr ->
            pwr.writeObject(PemObject("PUBLIC KEY", this.encoded))
            pwr.flush()
        }
        wr.toString()
    }

@JvmSynthetic
internal fun ByteArray.derToJose(algorithm: JWSAlgorithm = JWSAlgorithm.ES256): ByteArray {
    val len = ECDSA.getSignatureByteArrayLength(algorithm)
    return ECDSA.transcodeSignatureToConcat(this, len)
}


internal fun Display?.toMetaData(
    uniqueDocumentId: DocumentId
): DocumentMetaData? {
    fun Display.Image?.toMetaDataImage(): Image? {
        if (this == null) return null
        return Image(
            url = uri?.toString(),
            contentDescription = alternativeText
        )
    }

    if (this == null) return null

    return DocumentMetaData(
        uniqueDocumentId = uniqueDocumentId,
        documentName = name,
        logo = logo.toMetaDataImage(),
        backgroundColor = backgroundColor,
        textColor = textColor,
        backgroundImage = backgroundImage.toMetaDataImage()
    )
}