/*
 *  Copyright (c) 2023 European Commission
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

package eu.europa.ec.eudi.wallet.transfer.openid4vp

import android.content.Context
import android.util.Log
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.storage.AndroidStorageEngine
import com.android.identity.credential.CredentialRequest
import com.android.identity.credential.CredentialStore
import com.android.identity.credential.NameSpacedData
import com.android.identity.mdoc.mso.StaticAuthDataGenerator
import com.android.identity.mdoc.mso.StaticAuthDataParser
import com.android.identity.mdoc.response.DeviceResponseGenerator
import com.android.identity.mdoc.response.DocumentGenerator
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.storage.StorageEngine
import com.android.identity.util.Constants
import com.android.identity.util.Timestamp
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import com.upokecenter.cbor.CBORObject
import de.authada.eewa.wallet.PersonalData
import eu.europa.ec.eudi.iso18013.transfer.DisclosedDocument
import eu.europa.ec.eudi.iso18013.transfer.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.DocItem
import eu.europa.ec.eudi.iso18013.transfer.ReaderAuth
import eu.europa.ec.eudi.iso18013.transfer.RequestedDocumentData
import eu.europa.ec.eudi.iso18013.transfer.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStore
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseGenerator
import eu.europa.ec.eudi.iso18013.transfer.response.SessionTranscriptBytes
import eu.europa.ec.eudi.openid4vp.JarmRequirement
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.VpToken
import eu.europa.ec.eudi.openid4vp.legalName
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.JsonPointer
import eu.europa.ec.eudi.sdjwt.JwtAndClaims
import eu.europa.ec.eudi.sdjwt.KeyBindingSigner
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdJwtVerifier
import eu.europa.ec.eudi.sdjwt.asClaims
import eu.europa.ec.eudi.sdjwt.present
import eu.europa.ec.eudi.sdjwt.serializeWithKeyBinding
import eu.europa.ec.eudi.wallet.EudiWallet
import eu.europa.ec.eudi.wallet.document.Document.Companion.PROXY_ID_PREFIX
import eu.europa.ec.eudi.wallet.document.Document.Companion.SE_ID_PREFIX
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.Format
import eu.europa.ec.eudi.wallet.document.asNameSpacedData
import eu.europa.ec.eudi.wallet.document.getSeStoredCredentialMap
import eu.europa.ec.eudi.wallet.document.toDigestIdMapping
import eu.europa.ec.eudi.wallet.internal.Openid4VpX509CertificateTrust
import eu.europa.ec.eudi.wallet.issue.openid4vci.CredentialFormat
import eu.europa.ec.eudi.wallet.issue.openid4vci.IssueEvent
import eu.europa.ec.eudi.wallet.issue.openid4vci.derToJose
import eu.europa.ec.eudi.wallet.transfer.FormatDocRequest
import eu.europa.ec.eudi.wallet.transfer.FormatDocumentsResolver
import eu.europa.ec.eudi.wallet.transfer.FormatRequestDocument
import eu.europa.ec.eudi.wallet.transfer.toTransferObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.Date
import java.util.concurrent.Executor

private const val TAG = "OpenId4VpCBORResponseGe"

/**
 * OpenId4VpCBORResponseGeneratorImpl class is used for parsing a request (Presentation Definition) and generating the DeviceResponse
 *
 * @param documentsResolver document manager instance
 * @param storageEngine storage engine used to store documents
 * @param secureArea secure area used to store documents' keys
 */
class OpenId4VpResponseGeneratorImpl(
    private val documentsResolver: FormatDocumentsResolver,
    private val storageEngine: StorageEngine,
    private val secureArea: AndroidKeystoreSecureArea,
    private val documentManagerImpl: DocumentManager,
    private var readerTrustStore: ReaderTrustStore? = null,
) : ResponseGenerator<OpenId4VpRequest>() {

    private val openid4VpX509CertificateTrust = Openid4VpX509CertificateTrust(readerTrustStore)

    /**
     * Set a trust store so that reader authentication can be performed.
     *
     * If it is not provided, reader authentication will not be performed.
     *
     * @param readerTrustStore a trust store for reader authentication, e.g. DefaultReaderTrustStore
     */
    override fun setReaderTrustStore(readerTrustStore: ReaderTrustStore) = apply {
        openid4VpX509CertificateTrust.setReaderTrustStore(readerTrustStore)
        this.readerTrustStore = readerTrustStore
    }

    /**
     * Set a trust store so that reader authentication can be performed.
     *
     * If it is not provided, reader authentication will not be performed.
     *
     * @param readerTrustStore a trust store for reader authentication, e.g. DefaultReaderTrustStore
     */
    fun readerTrustStore(readerTrustStore: ReaderTrustStore) = apply {
        openid4VpX509CertificateTrust.setReaderTrustStore(readerTrustStore)
        this.readerTrustStore = readerTrustStore
    }

    internal fun getOpenid4VpX509CertificateTrust() = openid4VpX509CertificateTrust

    private data class LastRequestDetails(
        val sessionTranscript: SessionTranscriptBytes,
        val mdocGeneratedNonce: String,
        val requestAud: String,
        val requestNonce: String,
        val authKeyForAuthChannel: JWK?
    )

    private var lastRequestDetails: LastRequestDetails? = null

    private val secureAreaRepository: SecureAreaRepository by lazy {
        SecureAreaRepository().apply {
            addImplementation(secureArea)
        }
    }

    /** Parses a request and returns the requested document data
     * @param request the received request
     * @return [RequestedDocumentData]
     */
    override fun parseRequest(request: OpenId4VpRequest): RequestedDocumentData {
        lastRequestDetails = LastRequestDetails(
            sessionTranscript = request.sessionTranscript,
            mdocGeneratedNonce = request.mdocGeneratedNonce,
            requestNonce = request.openId4VPAuthorization.nonce,
            requestAud = request.openId4VPAuthorization.client.id,
            authKeyForAuthChannel = getKeyForAuthenticatedChannelIfRequired(request.openId4VPAuthorization)
        )
        return createRequestedDocumentData(
            requestedFields = request.openId4VPAuthorization.presentationDefinition.inputDescriptors
                .mapNotNull { inputDescriptor ->
                    val format =
                        inputDescriptor.format?.jsonObject()?.keys?.mapNotNull { formatString ->
                            Format.values().find { it.formatString == formatString }
                        }?.first() ?: Format.MSO_MDOC
                    val fields =
                        (inputDescriptor.id.value.trim() to format) to inputDescriptor.constraints.fields()
                            .mapNotNull { fieldConstraint ->
                                // path shall contain a requested data element as: $['<namespace>']['<data element identifier>']
                                when (format) {
                                    Format.SD_JWT_VC -> {
                                        val path = fieldConstraint.paths.first().value
                                        extractSdJwtField(path)?.let {
                                            inputDescriptor.id.value to it
                                        }
                                    }

                                    Format.MSO_MDOC -> {
                                        val path = fieldConstraint.paths.first().value
                                        extractMdocField(path)
                                    }

                                    Format.SE_TLV -> throw UnsupportedOperationException("se-tlv format not supported for presentation")
                                }

                            }.groupBy({ it.first }, { it.second })
                            .mapValues { (_, values) -> values.toList() }
                            .toMap()
                    fields
                }.toMap(),
            readerAuth = openid4VpX509CertificateTrust.getTrustResult()?.let { (chain, isTrusted) ->
                ReaderAuth(
                    byteArrayOf(0),
                    true, /* It is always true as siop-openid4vp library validates it internally and returns a fail status */
                    chain,
                    isTrusted,
                    request.openId4VPAuthorization.client.legalName() ?: "",
                )
            })
    }

    private fun extractMdocField(path: String): Pair<String, String>? =
        Regex("\\\$\\['(.*?)']\\['(.*?)']").find(path)
            ?.let { matchResult ->
                val (namespace, elementIdentifier) = matchResult.destructured
                if (namespace.isNotBlank() && elementIdentifier.isNotBlank()) {
                    namespace to elementIdentifier
                } else {
                    null
                }
            }

    private fun extractSdJwtField(
        path: String,
    ): String? = Regex("\\\$\\.(.+)").find(path)
        ?.let { matchResult ->
            val elementIdentifier =
                matchResult.destructured.component1()
            if (elementIdentifier.isNotBlank()) {
                elementIdentifier
            } else {
                null
            }
        }

    private fun getKeyForAuthenticatedChannelIfRequired(openId4VPAuthorization: ResolvedRequestObject.OpenId4VPAuthorization): JWK? {
        val format = openId4VPAuthorization.presentationDefinition.inputDescriptors.firstOrNull()?.format?.jsonObject()
        val authenticatedChannelAlgorithms = listOf(
            JWSAlgorithm("DVS-P256-SHA256-HS256").toJSONString(),
            JWSAlgorithm("DVS-P384-SHA256-HS256").toJSONString(),
            JWSAlgorithm("DVS-P512-SHA256-HS256").toJSONString()
        )
        val isAuthenticatedChannelRequired = try {
            when {
                format?.get("mso_mdoc") != null -> {
                    format["mso_mdoc"]?.jsonObject?.get("alg")?.jsonArray?.any {
                        authenticatedChannelAlgorithms.contains(it.toString())
                    } ?: false
                }
                format?.get("vc+sd-jwt") != null -> {
                    format["vc+sd-jwt"]?.jsonObject?.get("sd-jwt_alg_values")?.jsonArray?.any {
                        authenticatedChannelAlgorithms.contains(it.toString())
                    } ?: false
                }
                else -> false
            }
        }
        catch (e: Exception) {
            Log.e(TAG, "Exception during parsing json from verifier to check for authenticated channel requirement:", e)
            false
        }
        return if(isAuthenticatedChannelRequired) {
            val keyFromVerifierForPidIssuing = (openId4VPAuthorization.jarmRequirement as? JarmRequirement.Encrypted)?.encryptionKeySet?.keys?.firstOrNull()
            Log.d(TAG, "Authenticated Channel is required, this key will be set: " + keyFromVerifierForPidIssuing)
            keyFromVerifierForPidIssuing
        } else {
            Log.d(TAG, "No Authenticated Channel requested by Verifier")
            null
        }
    }

    /**
     * Creates a response and returns a ResponseResult
     *
     * @param disclosedDocuments a [List] of [DisclosedDocument]
     * @return a [ResponseResult]
     */
    override fun createResponse(
        disclosedDocuments: DisclosedDocuments
    ): ResponseResult {
        try {
            val requestDetails = requireNotNull(lastRequestDetails, {"lastRequestDetails is null, parseRequest() not yet called?"})
            val formatMap = disclosedDocuments.documents.groupBy {
                documentManagerImpl.getDocumentById(it.documentId)!!.format
            }.toMap()
            val resultList: Set<OpenId4VPResponseResultItem> = formatMap.flatMap {
                when (it.key) {
                    Format.SD_JWT_VC -> it.value.let { requestedDocs ->
                        requestedDocs.map { responseDocument ->
                            val addResult = if (responseDocument.isProxy) {
                                val adhocDocument = issueAProxyDocument(
                                    unprocessedResponseDocument = responseDocument,
                                    format = CredentialFormat.SD_JWT_VC,
                                    keyForIssuingAuthChannel = requestDetails.authKeyForAuthChannel
                                )
                                generateKBJWT(
                                    adhocDocument,
                                    requestDetails.requestNonce,
                                    requestDetails.requestAud,
                                )
                            } else {
                                generateKBJWT(
                                    responseDocument,
                                    requestDetails.requestNonce,
                                    requestDetails.requestAud
                                )
                            }

                            val dataString = when (addResult) {
                                is AddDocumentToResponse.Success -> addResult.data as String
                                is AddDocumentToResponse.UserAuthRequired -> {
                                    return ResponseResult.UserAuthRequired(
                                        addResult.keyUnlockData.getCryptoObjectForSigning(SecureArea.ALGORITHM_ES256)
                                    )
                                }
                            }
                            OpenId4VPResponseResultItem(
                                Format.SD_JWT_VC,
                                listOf(responseDocument.docType),
                                VpToken.Generic(dataString)
                            )
                        }
                    }

                    Format.MSO_MDOC -> it.value.let { requestedDocs ->
                        val deviceResponse =
                            DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK)
                        val docTypeList = requestedDocs.map { responseDocument ->
                            if (responseDocument.docType == "org.iso.18013.5.1.mDL" && responseDocument.selectedDocItems.filter { docItem ->
                                    docItem.elementIdentifier.startsWith("age_over_")
                                            && docItem.namespace == "org.iso.18013.5.1"
                                }.size > 2) {
                                return ResponseResult.Failure(Exception("Device Response is not allowed to have more than to age_over_NN elements"))
                            }
                            val addResult = if (responseDocument.isProxy) {
                                val adhocDocument = issueAProxyDocument(
                                    unprocessedResponseDocument = responseDocument,
                                    format =CredentialFormat.MSO_MDOC,
                                    keyForIssuingAuthChannel = requestDetails.authKeyForAuthChannel
                                )
                                addDocumentToResponse(
                                    adhocDocument, requestDetails.sessionTranscript
                                )
                            } else {
                                addDocumentToResponse(
                                    responseDocument, requestDetails.sessionTranscript
                                )
                            }
                            when (addResult) {
                                is AddDocumentToResponse.Success -> deviceResponse.addDocument(
                                    addResult.data as ByteArray
                                )

                                is AddDocumentToResponse.UserAuthRequired -> {
                                    return ResponseResult.UserAuthRequired(
                                        addResult.keyUnlockData.getCryptoObjectForSigning(SecureArea.ALGORITHM_ES256)
                                    )
                                }
                            }
                            responseDocument.docType
                        }
                        listOf(
                            OpenId4VPResponseResultItem(
                                format = Format.MSO_MDOC,
                                documentIds = docTypeList,
                                data = VpToken.MsoMdoc(
                                    Base64.getUrlEncoder().withoutPadding()
                                        .encodeToString(deviceResponse.generate()),
                                    Base64URL.encode(requestDetails.mdocGeneratedNonce),
                                )
                            )
                        )
                    }

                    Format.SE_TLV -> throw UnsupportedOperationException("se-tlv format not supported for presentation")
                }
            }.toSet()
            lastRequestDetails = null
            return ResponseResult.Success(OpenId4VpResponse(resultList))
        } catch (e: Exception) {
            return ResponseResult.Failure(e)
        }
    }

    @Throws(IllegalStateException::class)
    private fun addDocumentToResponse(
        adhocDocument: AdhocDocument, transcript: ByteArray
    ): AddDocumentToResponse {
        val dataElements = mapToDataElements(adhocDocument.disclosedDocument)
        val request = CredentialRequest(dataElements)

        val issuerSigned =
            CBORObject.DecodeFromBytes(Base64URL.from(adhocDocument.credential).decode())

        val issuerAuthBytes = issuerSigned["issuerAuth"].EncodeToBytes()
        val nameSpaces = issuerSigned["nameSpaces"]
        val digestIdMapping = nameSpaces.toDigestIdMapping()
        val staticAuthDataBytes =
            StaticAuthDataGenerator(digestIdMapping, issuerAuthBytes).generate()

        val nameSpacedData = nameSpaces.asNameSpacedData()
        val staticAuthData = StaticAuthDataParser(staticAuthDataBytes).parse()
        val mergedIssuerNamespaces = MdocUtil.mergeIssuerNamesSpaces(
            request, nameSpacedData, staticAuthData
        )
        val keyUnlockData =
            AndroidKeystoreSecureArea.KeyUnlockData(adhocDocument.disclosedDocument.documentId)
        try {
            val generator = DocumentGenerator(
                adhocDocument.disclosedDocument.docType, staticAuthData.issuerAuth, transcript
            ).setIssuerNamespaces(mergedIssuerNamespaces)
            generator.setDeviceNamespacesSignature(
                NameSpacedData.Builder().build(),
                secureArea,
                adhocDocument.disclosedDocument.documentId,
                keyUnlockData,
                SecureArea.ALGORITHM_ES256
            )
            return AddDocumentToResponse.Success(
                generator.generate(), adhocDocument.disclosedDocument.docType, Format.MSO_MDOC
            )
        } catch (lockedException: SecureArea.KeyLockedException) {
            Log.e(TAG, "error", lockedException)
            return AddDocumentToResponse.UserAuthRequired(keyUnlockData)
        }
    }


    @Throws(IllegalStateException::class)
    private fun addDocumentToResponse(
        disclosedDocument: DisclosedDocument, transcript: ByteArray
    ): AddDocumentToResponse {
        val dataElements = mapToDataElements(disclosedDocument)
        val request = CredentialRequest(dataElements)
        val credentialStore = CredentialStore(storageEngine, secureAreaRepository)
        val credential =
            requireNotNull(credentialStore.lookupCredential(disclosedDocument.documentId))
        val authKeyTimestamp = authKeyTimestamp()
        val authKey = credential.findAuthenticationKey(authKeyTimestamp)
            ?: throw IllegalStateException("No auth key available")
        val staticAuthData = StaticAuthDataParser(authKey.issuerProvidedData).parse()
        val mergedIssuerNamespaces = MdocUtil.mergeIssuerNamesSpaces(
            request, credential.nameSpacedData, staticAuthData
        )
        val keyUnlockData = AndroidKeystoreSecureArea.KeyUnlockData(authKey.alias)
        try {
            val generator = DocumentGenerator(
                disclosedDocument.docType,
                staticAuthData.issuerAuth,
                transcript
            ).setIssuerNamespaces(mergedIssuerNamespaces)
            generator.setDeviceNamespacesSignature(
                NameSpacedData.Builder().build(),
                authKey.secureArea,
                authKey.alias,
                keyUnlockData,
                SecureArea.ALGORITHM_ES256
            )
            return AddDocumentToResponse.Success(
                generator.generate(), disclosedDocument.docType, Format.MSO_MDOC
            )
        } catch (lockedException: SecureArea.KeyLockedException) {
            Log.e(TAG, "error", lockedException)
            return AddDocumentToResponse.UserAuthRequired(keyUnlockData)
        }
    }

    private fun authKeyTimestamp(): Timestamp {
        val gracePeriodForValidityIfDevicesTimeIsBehind = Duration.ofSeconds(10)
        val timestampToCheckForValidity =
            Instant.now() + gracePeriodForValidityIfDevicesTimeIsBehind
        return Timestamp.ofEpochMilli(timestampToCheckForValidity.toEpochMilli())
    }


    @Throws(IllegalStateException::class)
    private fun generateKBJWT(
        disclosedDocument: DisclosedDocument,
        nonce: String,
        aud: String,
    ): AddDocumentToResponse {
        val dataElements = mapToDataElements(disclosedDocument)
        val request = CredentialRequest(dataElements)

        return if (disclosedDocument.isInSecureElement) {
            kbJwtFromSecureElement(disclosedDocument, nonce, aud, dataElements)
        } else {
            kbJwtFromAndroidKeyStore(disclosedDocument, request, aud, nonce)
        }
    }

    @Throws(IllegalStateException::class)
    private fun generateKBJWT(
        adhocDocument: AdhocDocument,
        nonce: String,
        aud: String,
    ): AddDocumentToResponse {
        val dataElements = mapToDataElements(adhocDocument.disclosedDocument)
        val request = CredentialRequest(dataElements)

        return adHocKbJwt(adhocDocument, request, aud, nonce)
    }

    private fun mapToDataElements(disclosedDocument: DisclosedDocument) =
        disclosedDocument.selectedDocItems.map {
            CredentialRequest.DataElement(it.namespace, it.elementIdentifier, false)
        }

    private fun kbJwtFromSecureElement(
        disclosedDocument: DisclosedDocument,
        nonce: String,
        aud: String,
        dataElements: List<CredentialRequest.DataElement>
    ): AddDocumentToResponse.Success {
        val data = EudiWallet.secureElementPidLib?.let {
            val credentialHandle =
                storageEngine.getSeStoredCredentialMap()[disclosedDocument.documentId]
                    ?: throw IllegalStateException("Document not in secure element")
            it.createPid(lastRequestDetails?.authKeyForAuthChannel?.toECKey()?.toECPublicKey()
                ?: throw IllegalStateException("Authenticated channel key required for issuing with secure element"),
                credentialHandle,
                nonce.toByteArray(Charsets.UTF_8),
                aud,
                dataElements.flatMap { dataElement ->
                    PersonalData.values().filter {
                        it.attributeName.contentEquals(
                            dataElement.dataElementName, true
                        )
                    }
                }).pidString
        } ?: IllegalStateException("Failed to fetch secure element document")
        return AddDocumentToResponse.Success(data, disclosedDocument.docType, Format.SD_JWT_VC)
    }

    @Suppress("UNCHECKED_CAST")
    private fun kbJwtFromAndroidKeyStore(
        disclosedDocument: DisclosedDocument,
        request: CredentialRequest,
        aud: String,
        nonce: String
    ): AddDocumentToResponse {
        val credentialStore = CredentialStore(storageEngine, secureAreaRepository)
        val credential =
            requireNotNull(credentialStore.lookupCredential(disclosedDocument.documentId))
        val authKey = credential.findAuthenticationKey(authKeyTimestamp())
            ?: throw IllegalStateException("No auth key available")

        val credentialData = authKey.issuerProvidedData.toString(Charsets.UTF_8)
        val sdJwt: Result<SdJwt.Issuance<JwtAndClaims>> = SdJwtVerifier.verifyIssuance({
            SignedJWT.parse(it).jwtClaimsSet.asClaims()
        }, credentialData)

        val sdJwtIssuance = sdJwt.getOrThrow()

        val signedSdJwt = SdJwt.Issuance<SignedJWT>(
            SignedJWT.parse(sdJwtIssuance.jwt.first),
            sdJwtIssuance.disclosures
        )

        val pointer: Set<JsonPointer> = request.requestedDataElements.map {
            JsonPointer.parse("/${it.dataElementName}")!!
        }.toSet()
        val presentation: SdJwt.Presentation<SignedJWT> = signedSdJwt.present(pointer)!!

        val keyUnlockData = AndroidKeystoreSecureArea.KeyUnlockData(authKey.alias)
        try {
            val hashAlgorithmName =
                signedSdJwt.jwt.jwtClaimsSet.getStringClaim("_sd_alg")
            val hashAlgorithm = HashAlgorithm.fromString(hashAlgorithmName)!!
            val signatureCallback: (ByteArray) -> ByteArray = { data ->
                authKey.secureArea.sign(
                    authKey.alias, SecureArea.ALGORITHM_ES256, data, keyUnlockData
                )
            }

            val sdJwtWithKbJwt = presentation.serializeWithKeyBinding(
                hashAlgorithm, KeyBindingSignerImpl(
                    JWK.parse(signedSdJwt.jwt.jwtClaimsSet.getJSONObjectClaim("cnf")["jwk"] as Map<String, Any>),
                    JWSAlgorithm.ES256,
                    signatureCallback
                )
            ) {
                issueTime(Date.from(Instant.now()))
                audience(aud)
                claim("nonce", nonce)
                build()
            }
            @Suppress("UNCHECKED_CAST") return AddDocumentToResponse.Success(
                sdJwtWithKbJwt, disclosedDocument.docType, Format.SD_JWT_VC
            )

        } catch (lockedException: SecureArea.KeyLockedException) {
            Log.e(TAG, "error", lockedException)
            return AddDocumentToResponse.UserAuthRequired(keyUnlockData)
        }
    }

    private fun adHocKbJwt(
        adhocDocument: AdhocDocument, request: CredentialRequest, aud: String, nonce: String
    ): AddDocumentToResponse {
        val sdJwt: Result<SdJwt.Issuance<JwtAndClaims>> = SdJwtVerifier.verifyIssuance({
            SignedJWT.parse(it).jwtClaimsSet.asClaims()
        }, adhocDocument.credential)

        val sdJwtIssuance = sdJwt.getOrThrow()

        val signedSdJwt = SdJwt.Issuance<SignedJWT>(
            SignedJWT.parse(sdJwtIssuance.jwt.first), sdJwtIssuance.disclosures
        )

        val pointer: Set<JsonPointer> = request.requestedDataElements.map {
            JsonPointer.parse("/${it.dataElementName}")!!
        }.toSet()
        val presentation: SdJwt.Presentation<SignedJWT> = signedSdJwt.present(pointer)!!

        val keyUnlockData =
            AndroidKeystoreSecureArea.KeyUnlockData(adhocDocument.disclosedDocument.documentId)
        try {
            val hashAlgorithmName = signedSdJwt.jwt.jwtClaimsSet.getStringClaim("_sd_alg")
            val hashAlgorithm = HashAlgorithm.fromString(hashAlgorithmName)!!
            val signatureCallback: (ByteArray) -> ByteArray = { data ->
                secureArea.sign(
                    adhocDocument.disclosedDocument.documentId,
                    SecureArea.ALGORITHM_ES256,
                    data,
                    keyUnlockData
                )
            }

            val sdJwtWithKbJwt = presentation.serializeWithKeyBinding(
                hashAlgorithm, KeyBindingSignerImpl(
                    JWK.parse(signedSdJwt.jwt.jwtClaimsSet.getJSONObjectClaim("cnf")["jwk"] as Map<String, Any>),
                    JWSAlgorithm.ES256,
                    signatureCallback
                )
            ) {
                issueTime(Date.from(Instant.now()))
                audience(aud)
                claim("nonce", nonce)
                build()
            }
            @Suppress("UNCHECKED_CAST")
            return AddDocumentToResponse.Success(
                sdJwtWithKbJwt,
                adhocDocument.disclosedDocument.docType,
                Format.SD_JWT_VC,
            )

        } catch (lockedException: SecureArea.KeyLockedException) {
            Log.e(TAG, "error", lockedException)
            return AddDocumentToResponse.UserAuthRequired(keyUnlockData)
        }
    }

    private class KeyBindingSignerImpl(
        override val publicKey: JWK,
        override val signAlgorithm: JWSAlgorithm,
        private val signatureFunction: (ByteArray) -> ByteArray
    ) : KeyBindingSigner {
        override fun getJCAContext(): JCAContext {
            return JCAContext()
        }

        override fun sign(p0: JWSHeader, p1: ByteArray): Base64URL {
            return Base64URL.encode(signatureFunction(p1).derToJose(signAlgorithm))
        }

    }

    private fun createRequestedDocumentData(
        requestedFields: Map<Pair<String, Format>, Map<String, List<String>>>,
        readerAuth: ReaderAuth?,
    ): RequestedDocumentData {
        //requestedFields contains key "eu.europa.ec.eudiw.pid.1", and values like "family_name"
        val requestedDocuments = mutableListOf<FormatRequestDocument>()
        requestedFields.forEach { document ->
            // create doc item
            val docItems = mutableListOf<DocItem>()
            document.value.forEach { (namespace, elementIds) ->
                elementIds.forEach { elementId ->
                    docItems.add(DocItem(namespace, elementId))
                }
            }
            val (docType, format) = document.key

            requestedDocuments.addAll(
                documentsResolver.resolveDocuments(
                    FormatDocRequest(
                        format,
                        docType, //"eu.europa.ec.eudiw.pid.1"
                        docItems, //DocItem("eu.europa.ec.eudiw.pid.1", "family_name")
                        readerAuth //null
                    )
                )
            )

            if (requestedDocuments.isEmpty()) { //TODO: also check if the session is without secure element
                //Add some random document to trick wallet into thinking there is something FIXME one day
                requestedDocuments.add(
                    FormatRequestDocument(
                        documentId = "0932574d-4b05-4553-9e58-5a786aed723a", //some id
                        docType = docType, //"eu.europa.ec.eudiw.pid.1"
                        docName = "EU PID",
                        userAuthentication = false,
                        docRequest = FormatDocRequest(
                            format,
                            docType,
                            docItems,
                            readerAuth
                        )
                    )
                )
            }
        }

        return RequestedDocumentData(requestedDocuments.map { it.toTransferObject() })
    }

    class Builder(context: Context) {
        private val _context = context.applicationContext
        var formatDocumentsResolver: FormatDocumentsResolver? = null
        var documentManager: DocumentManager? = null
        var readerTrustStore: ReaderTrustStore? = null

        /**
         * Reader trust store that will be used to validate the certificate chain of the mdoc verifier
         *
         * @param readerTrustStore
         */
        fun readerTrustStore(readerTrustStore: ReaderTrustStore) =
            apply { this.readerTrustStore = readerTrustStore }

        fun build(): OpenId4VpResponseGeneratorImpl {
            return formatDocumentsResolver?.let { documentsResolver ->
                OpenId4VpResponseGeneratorImpl(
                    documentsResolver,
                    storageEngine,
                    androidSecureArea,
                    documentManager!!,
                ).apply {
                    readerTrustStore?.let { setReaderTrustStore(it) }
                }
            } ?: throw IllegalArgumentException("documentResolver not set")
        }

        private val storageEngine: StorageEngine
            get() = AndroidStorageEngine.Builder(_context, _context.noBackupFilesDir)
                .setUseEncryption(true)
                .build()
        private val androidSecureArea: AndroidKeystoreSecureArea
            get() = AndroidKeystoreSecureArea(_context, storageEngine)
    }

    inner class ThisThreadExecutor : Executor {
        override fun execute(command: Runnable) {
            command.run()
        }
    }

    private fun issueAProxyDocument(
        unprocessedResponseDocument: DisclosedDocument,
        format: CredentialFormat,
        keyForIssuingAuthChannel: JWK?
    ): AdhocDocument {
        val tbdResponseDocument: MutableMap<DisclosedDocument, String> = mutableMapOf()
        Log.d(
            TAG,
            "issueAProxyDocument() entered tbdResponseDocument should be empty"
        )
        EudiWallet.issueDocumentByDocTypeAndFormat(
            docType = unprocessedResponseDocument.docType,
            docItems = unprocessedResponseDocument.selectedDocItems,
            formats = setOf(format),
            onEvent = {
                when (it) {
                    is IssueEvent.DocumentIssued -> {
                        Log.d(
                            TAG,
                            "issueAProxyDocument() issued document of type ${it.docType} with it: ${it.documentId}"
                        )
                        tbdResponseDocument.put(
                            DisclosedDocument(
                                it.documentId,
                                unprocessedResponseDocument.docType,
                                unprocessedResponseDocument.selectedDocItems,
                                unprocessedResponseDocument.docRequest
                            ), it.credential
                        )
                    }

                    is IssueEvent.Failure -> {
                        Log.e(TAG, "issueAProxyDocument() IssueEvent.Failure", it.cause)
                        throw RuntimeException(it.cause)
                    }

                    else -> {
                        Log.i(TAG, "issueAProxyDocument() state: $it")
                    }
                }
            },
            executor = ThisThreadExecutor(),
            keyForIssuingAuthChannelThisMethod = keyForIssuingAuthChannel,
            storeDocument = false
        )
        val document = tbdResponseDocument.entries.firstOrNull()?.let {
            AdhocDocument(it.key, it.value)
        }

        Log.d(
            TAG,
            "issueAProxyDocument() before return tbdResponseDocument contains IDs = ${tbdResponseDocument.map { it.key.documentId }}"
        )

        return document ?: throw RuntimeException("Just issued document not yet available")
    }

    data class AdhocDocument(val disclosedDocument: DisclosedDocument, val credential: String)

    private sealed interface AddDocumentToResponse {
        data class Success(val data: Any, val docType: String, val format: Format) :
            AddDocumentToResponse

        data class UserAuthRequired(val keyUnlockData: AndroidKeystoreSecureArea.KeyUnlockData) :
            AddDocumentToResponse
    }


    private val DisclosedDocument.isProxy: Boolean
        get() = this.documentId.startsWith(PROXY_ID_PREFIX)
    private val DisclosedDocument.isInSecureElement: Boolean
        get() = this.documentId.startsWith(SE_ID_PREFIX)
}