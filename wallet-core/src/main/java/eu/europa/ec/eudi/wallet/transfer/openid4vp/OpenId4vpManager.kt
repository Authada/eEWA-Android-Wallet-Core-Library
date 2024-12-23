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
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.iso18013.transfer.TransferEvent
import eu.europa.ec.eudi.iso18013.transfer.response.SessionTranscriptBytes
import eu.europa.ec.eudi.openid4vp.Consensus
import eu.europa.ec.eudi.openid4vp.DispatchOutcome
import eu.europa.ec.eudi.openid4vp.JarmConfiguration
import eu.europa.ec.eudi.openid4vp.JwkSetSource
import eu.europa.ec.eudi.openid4vp.PreregisteredClient
import eu.europa.ec.eudi.openid4vp.Resolution
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.ResponseMode
import eu.europa.ec.eudi.openid4vp.SiopOpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.SiopOpenId4Vp
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme
import eu.europa.ec.eudi.openid4vp.asException
import eu.europa.ec.eudi.prex.DescriptorMap
import eu.europa.ec.eudi.prex.Id
import eu.europa.ec.eudi.prex.JsonPath
import eu.europa.ec.eudi.prex.PresentationSubmission
import eu.europa.ec.eudi.wallet.internal.Openid4VpUtils
import eu.europa.ec.eudi.wallet.internal.mainExecutor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.bouncycastle.util.encoders.Hex
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.Executor

/**
 * OpenId4vp manager. This class is used to manage the OpenId4vp transfer method. It is used to resolve the request uri and send the response.
 *
 * Example:
 * ```
 * val certificates = listOf<X509Certificate>(
 *     // put trusted reader certificates here
 * )
 * val readerTrustStore = ReaderTrustStore.getDefault(
 *     listOf(context.applicationContext.getCertificate(certificates))
 * )
 *
 * val documentedResolver = DocumentResolver { docRequest: DocRequest ->
 *     // put your code here to resolve the document
 *     // usually document resolution is done based on `docRequest.docType`
 * }
 *
 * val openid4VpCBORResponseGenerator = OpenId4VpCBORResponseGeneratorImpl.Builder(context)
 *                 .readerTrustStore(readerTrustStore)
 *                 .documentsResolver(documentedResolver)
 *                 .build()
 *
 * val openId4vpManager = OpenId4vpManager(
 *    context,
 *    OpenId4VpConfig.Builder()
 *             .withClientIdSchemes(
 *             listOf(
 *                 ClientIdScheme.Preregistered(
 *                     listOf(
 *                         PreregisteredVerifier(
 *                             "VerifierClientId",
 *                             "VerifierLegalName",
 *                             "https://example.com"
 *                         )
 *                     )
 *                 ),
 *                 ClientIdScheme.X509SanDns
 *             ))
 *             .withEncryptionAlgorithms(listOf(EncryptionAlgorithm.ECDH_ES))
 *             .withEncryptionMethods(listOf(EncryptionMethod.A128CBC_HS256))
 *             .build(),
 *    openid4VpCBORResponseGenerator
 * )
 * val transferEventListener = TransferEvent.Listener { event ->
 *   when (event) {
 *      is TransferEvent.Connecting -> {
 *          // inform user
 *      }
 *      is Transfer.Redirect -> {
 *          val redirect_uri = event.redirectUri
 *          // redirect user to the given URI
 *      }
 *      is TransferEvent.RequestReceived -> {
 *          val request = openId4vpManager.resolveRequestUri(event.request)
 *          // handle request and demand from user the documents to be disclosed
 *          val disclosedDocuments = listOf<DisclosedDocument>()
 *          val response = openid4VpCBORResponseGenerator.createResponse(disclosedDocuments)
 *          openId4vpManager.sendResponse(response.deviceResponseBytes)
 *      }
 *   }
 * }
 * openId4vpManager.addTransferEventListener(transferEventListener)
 *
 * // resolve a request URI
 * openId4vpManager.resolveRequestUri(requestURI)
 *
 * ```
 * @param context the application context
 * @param openId4VpConfig the configuration for OpenId4Vp
 * @param responseGenerator that parses the request and creates the response
 */

private const val TAG = "OpenId4vpManager"

class OpenId4vpManager(
    context: Context,
    openId4VpConfig: OpenId4VpConfig,
    val responseGenerator: OpenId4VpResponseGeneratorImpl,
) : TransferEvent.Listenable {

    private val appContext = context.applicationContext
    private val ioScope = CoroutineScope(Job() + Dispatchers.IO)
    private var executor: Executor? = null

    private var transferEventListeners: MutableList<TransferEvent.Listener> = mutableListOf()
    private val onResultUnderExecutor = { result: TransferEvent ->
        (executor ?: appContext.mainExecutor()).execute {
            Log.d(TAG, "onResultUnderExecutor $result")
            transferEventListeners.onTransferEvent(result)
        }
    }

    private val siopOpenId4Vp = SiopOpenId4Vp(openId4VpConfig.toSiopOpenId4VPConfig())
    private var resolvedRequestObject: ResolvedRequestObject? = null
    private var mdocGeneratedNonce: String? = null

    /**
     * Setting the `executor` is optional and defines the executor that will be used to
     * execute the callback. If the `executor` is not defined, the callback will be executed on the
     * main thread.
     * @param Executor the executor to use for callbacks. If null, the main executor will be used.
     */
    fun setExecutor(executor: Executor) {
        this.executor = executor
    }

    /**
     * Resolve a request uri
     *
     * @param openid4VPURI
     */
    fun resolveRequestUri(openid4VPURI: String) {
        Log.d(
            TAG,
            "Resolve request uri: ${URLDecoder.decode(openid4VPURI, StandardCharsets.UTF_8.name())}"
        )
        ioScope.launch {
            onResultUnderExecutor(TransferEvent.Connecting)
            runCatching { siopOpenId4Vp.resolveRequestUri(openid4VPURI) }.onSuccess { resolution ->
                when (resolution) {
                    is Resolution.Invalid -> {
                        Log.e(TAG, "Resolution.Invalid", resolution.error.asException())
                        onResultUnderExecutor(TransferEvent.Error(resolution.error.asException()))
                    }

                    is Resolution.Success -> {
                        Log.d(TAG, "Resolution.Success")
                        resolution.requestObject
                            .also { resolvedRequestObject = it }
                            .let { requestObject ->
                                when (requestObject) {
                                    is ResolvedRequestObject.OpenId4VPAuthorization -> {
                                        Log.d(TAG, "OpenId4VPAuthorization Request received")
                                        val (sessionTranscript, mDocGeneratedNonce) = requestObject.toSessionTranscript()
                                        val request = OpenId4VpRequest(
                                            requestObject,
                                            sessionTranscript,
                                            mDocGeneratedNonce
                                        )
                                        val requestedDocumentData =
                                            responseGenerator.parseRequest(request)
                                        onResultUnderExecutor(
                                            TransferEvent.RequestReceived(
                                                requestedDocumentData = requestedDocumentData,
                                                request = request
                                            )
                                        )
                                    }

                                    is ResolvedRequestObject.SiopAuthentication -> {
                                        Log.w(TAG, "SiopAuthentication Request received")
                                        onResultUnderExecutor("SiopAuthentication request received, not supported yet.".err())
                                    }

                                    is ResolvedRequestObject.SiopOpenId4VPAuthentication -> {
                                        Log.w(TAG, "SiopOpenId4VPAuthentication Request received")
                                        onResultUnderExecutor("SiopAuthentication request received, not supported yet.".err())
                                    }

                                    else -> {
                                        Log.w(TAG, "Unknown request received")
                                        onResultUnderExecutor("Unknown request received".err())
                                    }
                                }
                            }
                    }
                }
            }.onFailure {
                Log.e(TAG, "An error occurred resolving request uri: $openid4VPURI", it)
                onResultUnderExecutor(TransferEvent.Error(it))
            }
        }
    }


    /**
     * Sends a response to the verifier
     *
     * @param deviceResponse
     */
    fun sendResponse(vpToken: OpenId4VPResponseResultItem) {
        ioScope.launch {
            resolvedRequestObject?.let { resolvedRequestObject ->
                when (resolvedRequestObject) {
                    is ResolvedRequestObject.OpenId4VPAuthorization -> {

                        Log.d(TAG, "VpToken: $vpToken")

                        val presentationDefinition =
                            (resolvedRequestObject).presentationDefinition
                        val consensus = Consensus.PositiveConsensus.VPTokenConsensus(
                            vpToken.data,
                            presentationSubmission = PresentationSubmission(
                                id = Id(UUID.randomUUID().toString()),
                                definitionId = presentationDefinition.id,
                                presentationDefinition.inputDescriptors.map { inputDescriptor ->
                                    DescriptorMap(
                                        inputDescriptor.id,
                                        vpToken.format.formatString,
                                        path = JsonPath.jsonPath("$")!!
                                    )
                                }
                            )
                        )

                        runCatching {
                            siopOpenId4Vp.dispatch(
                                resolvedRequestObject,
                                consensus
                            )
                        }.onSuccess { dispatchOutcome ->
                            when (dispatchOutcome) {
                                is DispatchOutcome.VerifierResponse.Accepted -> {
                                    Log.d(
                                        TAG,
                                        "VerifierResponse Accepted with redirectUri: $dispatchOutcome.redirectURI"
                                    )
                                    onResultUnderExecutor(TransferEvent.ResponseSent)
                                    dispatchOutcome.redirectURI?.let {
                                        onResultUnderExecutor(TransferEvent.Redirect(it))
                                    }
                                }

                                is DispatchOutcome.VerifierResponse.Rejected -> {
                                    Log.d(TAG, "VerifierResponse Rejected")
                                    onResultUnderExecutor("DispatchOutcome: VerifierResponse Rejected".err())
                                }

                                is DispatchOutcome.RedirectURI -> {
                                    Log.d(TAG, "VerifierResponse RedirectURI")
                                    onResultUnderExecutor(TransferEvent.ResponseSent)
                                }
                            }
                            onResultUnderExecutor(TransferEvent.Disconnected)
                        }.onFailure {
                            Log.e(TAG, "An error occurred in dispatching", it)
                            onResultUnderExecutor(TransferEvent.Error(it))
                        }
                    }

                    else -> {
                        Log.e(TAG, "${resolvedRequestObject.javaClass} not supported yet.")
                        onResultUnderExecutor("${resolvedRequestObject.javaClass} not supported yet.".err())
                    }
                }
            }
        }
    }

    /**
     * Closes the OpenId4VpManager
     */
    fun close() {
        Log.d(TAG, "close")
        resolvedRequestObject = null
        mdocGeneratedNonce = null
    }

    private fun OpenId4VpConfig.toSiopOpenId4VPConfig(): SiopOpenId4VPConfig {
        return SiopOpenId4VPConfig(
            jarmConfiguration = JarmConfiguration.Encryption(
                supportedAlgorithms = this.encryptionAlgorithms.map {
                    JWEAlgorithm.parse(it.name)
                },
                supportedMethods = this.encryptionMethods.map {
                    EncryptionMethod.parse(it.name)
                },
            ),
            supportedClientIdSchemes = this.clientIdSchemes.map { clientIdScheme ->
                when (clientIdScheme) {
                    is ClientIdScheme.Preregistered -> SupportedClientIdScheme.Preregistered(
                        clientIdScheme.preregisteredVerifiers.associate { verifier ->
                            verifier.clientId to PreregisteredClient(
                                verifier.clientId,
                                verifier.legalName,
                                JWSAlgorithm.RS256 to JwkSetSource.ByReference(
                                    URI("${verifier.verifierApi}/wallet/public-keys.json")
                                )
                            )
                        }
                    )

                    is ClientIdScheme.X509SanDns ->
                        SupportedClientIdScheme.X509SanDns(responseGenerator.getOpenid4VpX509CertificateTrust())

                    is ClientIdScheme.X509SanUri ->
                        SupportedClientIdScheme.X509SanUri(responseGenerator.getOpenid4VpX509CertificateTrust())


                    is ClientIdScheme.VerifierAttestation ->
                        SupportedClientIdScheme.VerifierAttestation(
                            VerifierAttestationSignatureVerifier(
                                responseGenerator.getVerifierAttestationTrust()
                            )
                        )
                }
            }
        )
    }

    private fun ResolvedRequestObject.OpenId4VPAuthorization.toSessionTranscript(): MdocSessionTranscript {
        val clientId = this.client.id
        val responseUri =
            when (this.responseMode) {
                is ResponseMode.DirectPostJwt -> (this.responseMode as ResponseMode.DirectPostJwt?)
                    ?.responseURI

                is ResponseMode.DirectPost -> (this.responseMode as ResponseMode.DirectPost?)
                    ?.responseURI

                else -> null
            }?.toString() ?: ""
        val nonce = this.nonce
        val mdocGeneratedNonce = Openid4VpUtils.generateMdocGeneratedNonce().also {
            mdocGeneratedNonce = it
        }

        val sessionTranscriptBytes = Openid4VpUtils.generateSessionTranscript(
            clientId,
            responseUri,
            nonce,
            mdocGeneratedNonce
        )
        Log.d(
            TAG,
            "Session Transcript: ${
                Hex.toHexString(sessionTranscriptBytes)
            }, for clientId: $clientId, responseUri: $responseUri, nonce: $nonce, mdocGeneratedNonce: $mdocGeneratedNonce"
        )
        return MdocSessionTranscript(sessionTranscriptBytes, mdocGeneratedNonce)
    }

    data class MdocSessionTranscript(
        val sessionTranscriptBytes: SessionTranscriptBytes,
        val generatedNonce: String
    )

    private fun List<TransferEvent.Listener>.onTransferEvent(event: TransferEvent) {
        forEach { it.onTransferEvent(event) }
    }

    private fun String.err(): TransferEvent.Error {
        return TransferEvent.Error(Throwable(this))
    }

    override fun addTransferEventListener(listener: TransferEvent.Listener): OpenId4vpManager =
        apply {
            transferEventListeners.add(listener)
        }

    override fun removeTransferEventListener(listener: TransferEvent.Listener): OpenId4vpManager =
        apply {
            transferEventListeners.remove(listener)
        }

    override fun removeAllTransferEventListeners(): OpenId4vpManager = apply {
        transferEventListeners.clear()
    }
}