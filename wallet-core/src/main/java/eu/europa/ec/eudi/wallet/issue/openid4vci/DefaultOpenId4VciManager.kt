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

import android.content.Context
import android.content.Intent
import android.content.Intent.ACTION_VIEW
import android.net.Uri
import android.util.Log
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.iso18013.transfer.DocItem
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.VerifierKA
import eu.europa.ec.eudi.wallet.attestation.WalletAttestationProvider
import eu.europa.ec.eudi.wallet.document.AddDocumentResult
import eu.europa.ec.eudi.wallet.document.DocumentId
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.IssuanceRequest
import eu.europa.ec.eudi.wallet.document.internal.supportsStrongBox
import eu.europa.ec.eudi.wallet.internal.mainExecutor
import eu.europa.ec.eudi.wallet.issue.openid4vci.IssueEvent.Companion.failure
import kotlinx.coroutines.*
import net.minidev.json.JSONObject
import java.net.URI
import java.time.Clock
import java.util.*
import java.util.concurrent.Executor

internal class DefaultOpenId4VciManager(
    private val context: Context,
    private val documentManager: DocumentManager,
    var config: OpenId4VciManager.Config
) : OpenId4VciManager {

    private var suspendedAuthorization: SuspendedAuthorization? = null
    private val offerUriCache = mutableMapOf<String, Offer>()

    override fun issueDocumentByDocTypeAndSupportedFormats(
        docType: String,
        supportedFormats: Set<CredentialFormat>,
        executor: Executor?,
        onIssueEvent: OpenId4VciManager.OnIssueEvent,
        claims: List<DocItem>?,
        keyForIssuingAuthChannel: JWK?,
        storeDocument: Boolean
    ) {
        val listener = onIssueEvent.wrap(executor)
        clearStateThen {
            runBlocking {
                try {
                    val credentialIssuerId = CredentialIssuerId(config.issuerUrl).getOrThrow()
                    val (credentialIssuerMetadata, authorizationServerMetadata) = DefaultHttpClientFactory()
                        .use { client ->
                            Issuer.metaData(client, credentialIssuerId)
                        }
                    val configurationsFilter = DocTypeFilterFactory(docType, supportedFormats)
                    val filterList = listOf(
                        configurationsFilter,
                        ProofTypeFilter
                    )
                    val credentialConfigurationIds =
                        credentialIssuerMetadata.credentialConfigurationsSupported.filter { (_, conf) ->
                            filterList.all { filter -> filter(conf) }
                        }.keys.ifEmpty { throw IllegalStateException("No suitable configuration found") }

                    val credentialOffer = CredentialOffer(
                        credentialIssuerIdentifier = credentialIssuerId,
                        credentialIssuerMetadata = credentialIssuerMetadata,
                        authorizationServerMetadata = authorizationServerMetadata.first(),
                        credentialConfigurationIdentifiers = credentialConfigurationIds.toList(),
                        claims = mapClaimsToCredentialOffer(claims)
                    )

                    val offer = DefaultOffer(credentialOffer, filterList)
                    doIssueDocumentByOffer(offer, config, listener, keyForIssuingAuthChannel, storeDocument)

                } catch (e: Throwable) {
                    Log.e(TAG, "error during issueDocumentByDocType", e)
                    listener(failure(e))
                }
            }
        }
    }


    private fun mapClaimsToCredentialOffer(claims: List<DocItem>?): Map<String, Any> {
        val userSelectedClaims: Map<String, Map<String, JSONObject>>? =
            claims?.groupBy { it.namespace }?.mapValues {
                it.value.associate { docItem ->
                    docItem.elementIdentifier to JSONObject()
                }
            }?.toMap()

        return userSelectedClaims ?: emptyMap()
    }

    override fun issueDocumentByOffer(
        offer: Offer,
        executor: Executor?,
        onIssueEvent: OpenId4VciManager.OnIssueEvent
    ) {
        clearStateThen {
            launch(onIssueEvent.wrap(executor)) { coroutineScope, listener ->
                try {
                    doIssueDocumentByOffer(offer, config, listener, keyForIssuingAuthChannel = null)
                } catch (e: Throwable) {
                    listener(failure(e))
                    coroutineScope.cancel("issueDocumentByOffer failed", e)
                }
            }
        }
    }


    override fun issueDocumentByOfferUri(
        offerUri: String,
        executor: Executor?,
        onIssueEvent: OpenId4VciManager.OnIssueEvent
    ) {
        clearStateThen {
            launch(onIssueEvent.wrap(executor)) { coroutineScope, listener ->
                try {
                    val offer = offerUriCache[offerUri]
                        ?: CredentialOfferRequestResolver().resolve(offerUri).getOrThrow()
                            .let { DefaultOffer(it) }
                    doIssueDocumentByOffer(offer, config, listener, keyForIssuingAuthChannel = null)
                } catch (e: Throwable) {
                    listener(failure(e))
                    coroutineScope.cancel("issueDocumentByOffer failed", e)
                }
            }
        }
    }

    override fun resolveDocumentOffer(
        offerUri: String,
        executor: Executor?,
        onResolvedOffer: OpenId4VciManager.OnResolvedOffer
    ) {
        launch(onResolvedOffer.wrap(executor)) { coroutineScope, callback ->
            try {
                val credentialOffer =
                    CredentialOfferRequestResolver().resolve(offerUri).getOrThrow()
                val offer = DefaultOffer(credentialOffer)
                offerUriCache[offerUri] = offer
                callback(OfferResult.Success(offer))
                coroutineScope.cancel("resolveDocumentOffer succeeded")
            } catch (e: Throwable) {
                offerUriCache.remove(offerUri)
                callback(OfferResult.Failure(e))
                coroutineScope.cancel("resolveDocumentOffer failed", e)
            }
        }
    }

    override fun resumeWithAuthorization(intent: Intent) {
        suspendedAuthorization?.use { it.resumeFromIntent(intent) }
            ?: throw IllegalStateException("No authorization request to resume")
    }

    override fun resumeWithAuthorization(uri: String) {
        suspendedAuthorization?.use { it.resumeFromUri(uri) }
            ?: throw IllegalStateException("No authorization request to resume")
    }

    override fun resumeWithAuthorization(uri: Uri) {
        suspendedAuthorization?.use { it.resumeFromUri(uri) }
            ?: throw IllegalStateException("No authorization request to resume")
    }

    private suspend fun doIssueDocumentByOffer(
        offer: Offer,
        config: OpenId4VciManager.Config,
        onEvent: OpenId4VciManager.OnResult<IssueEvent>,
        keyForIssuingAuthChannel: JWK?,
        storeDocument: Boolean = true
    ) {
        offer as DefaultOffer
        val credentialOffer = offer.credentialOffer
        val issuer = Issuer.make(config.toOpenId4VCIConfig(context, keyForIssuingAuthChannel), credentialOffer).getOrThrow()
        onEvent(IssueEvent.Started(offer.offeredDocuments.size))
        with(issuer) {
            val prepareAuthorizationCodeRequest = prepareAuthorizationRequest().getOrThrow()
            val authResponse =
                openBrowserForAuthorization(prepareAuthorizationCodeRequest).getOrThrow()
            val authorizedRequest = prepareAuthorizationCodeRequest.authorizeWithAuthorizationCode(
                AuthorizationCode(authResponse.authorizationCode),
                authResponse.serverState
            ).getOrThrow()

            val addedDocuments = mutableSetOf<DocumentId>()

            offer.offeredDocuments.forEach { item ->
                val issuanceRequest = documentManager
                    .createIssuanceRequest(item, config.useStrongBoxIfSupported, storeDocument)
                    .getOrThrow()
                doIssueCredential(
                    authorizedRequest,
                    item.configurationIdentifier,
                    item.configuration,
                    issuanceRequest,
                    addedDocuments,
                    onEvent
                )
            }
            onEvent(IssueEvent.Finished(addedDocuments.toList()))
        }
    }


    private suspend fun openBrowserForAuthorization(prepareAuthorizationCodeRequest: AuthorizationRequestPrepared): Result<SuspendedAuthorization.Response> {
        val authorizationCodeUri =
            Uri.parse(prepareAuthorizationCodeRequest.authorizationCodeURL.value.toString())

        return suspendCancellableCoroutine { continuation ->
            suspendedAuthorization = SuspendedAuthorization(continuation)
            continuation.invokeOnCancellation {
                suspendedAuthorization = null
            }
            context.startActivity(Intent(ACTION_VIEW, authorizationCodeUri).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            })
        }
    }


    private suspend fun Issuer.doIssueCredential(
        authRequest: AuthorizedRequest,
        credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
        credentialConfiguration: CredentialConfiguration,
        issuanceRequest: IssuanceRequest,
        addedDocuments: MutableSet<DocumentId>,
        onEvent: OpenId4VciManager.OnResult<IssueEvent>
    ) {
        val payload =
            IssuanceRequestPayload.ConfigurationBased(credentialConfigurationIdentifier, null)
        when (authRequest) {
            is AuthorizedRequest.NoProofRequired -> doRequestSingleNoProof(
                authRequest,
                payload,
                credentialConfiguration,
                issuanceRequest,
                addedDocuments,
                onEvent
            )

            is AuthorizedRequest.ProofRequired -> doRequestSingleWithProof(
                authRequest,
                payload,
                credentialConfiguration,
                issuanceRequest,
                addedDocuments,
                onEvent
            )
        }
    }

    private suspend fun Issuer.doRequestSingleNoProof(
        authRequest: AuthorizedRequest.NoProofRequired,
        payload: IssuanceRequestPayload,
        credentialConfiguration: CredentialConfiguration,
        issuanceRequest: IssuanceRequest,
        addedDocuments: MutableSet<DocumentId>,
        onEvent: OpenId4VciManager.OnResult<IssueEvent>
    ) {
        when (val outcome = authRequest.requestSingle(payload).getOrThrow()) {
            is SubmittedRequest.InvalidProof -> doRequestSingleWithProof(
                authRequest.handleInvalidProof(outcome.cNonce),
                payload,
                credentialConfiguration,
                issuanceRequest,
                addedDocuments,
                onEvent
            )

            is SubmittedRequest.Failed -> onEvent(
                IssueEvent.DocumentFailed(
                    issuanceRequest,
                    outcome.error
                )
            )

            is SubmittedRequest.Success -> storeIssuedCredential(
                outcome.credentials[0],
                issuanceRequest,
                credentialConfiguration,
                onEvent,
                addedDocuments
            )
        }
    }

    private suspend fun Issuer.doRequestSingleWithProof(
        authRequest: AuthorizedRequest.ProofRequired,
        payload: IssuanceRequestPayload,
        credentialConfiguration: CredentialConfiguration,
        issuanceRequest: IssuanceRequest,
        addedDocuments: MutableSet<DocumentId>,
        onEvent: OpenId4VciManager.OnResult<IssueEvent>
    ) {
        val proofSigner = ProofSigner(credentialConfiguration.proofTypesSupported.values.map {
            it.type() to when (it) {
                is ProofTypeMeta.Jwt -> it.algorithms
                else -> emptyList()
            }
        }.toMap(), issuanceRequest).getOrThrow()
        try {
            when (val outcome =
                authRequest.requestSingle(payload, proofSigner.toPopSigner()).getOrThrow()) {
                is SubmittedRequest.Failed -> onEvent(
                    IssueEvent.DocumentFailed(
                        issuanceRequest,
                        outcome.error
                    )
                )

                is SubmittedRequest.InvalidProof -> onEvent(
                    IssueEvent.DocumentFailed(
                        issuanceRequest,
                        Exception(outcome.errorDescription)
                    )
                )

                is SubmittedRequest.Success -> storeIssuedCredential(
                    outcome.credentials[0],
                    issuanceRequest,
                    credentialConfiguration,
                    onEvent,
                    addedDocuments
                )
            }

        } catch (e: Throwable) {
            when (val status = proofSigner.userAuthStatus) {
                is ProofSigner.UserAuthStatus.Required -> {
                    val event = object :
                        IssueEvent.DocumentRequiresUserAuth(issuanceRequest, status.cryptoObject) {
                        override fun resume() {
                            runBlocking {
                                doRequestSingleWithProof(
                                    authRequest,
                                    payload,
                                    credentialConfiguration,
                                    issuanceRequest,
                                    addedDocuments,
                                    onEvent
                                )
                            }
                        }

                        override fun cancel() {
                            onEvent(IssueEvent.DocumentFailed(issuanceRequest, e.cause ?: e))
                        }
                    }
                    onEvent(event)
                }

                else -> onEvent(IssueEvent.DocumentFailed(issuanceRequest, e))
            }
        }
    }

    private fun storeIssuedCredential(
        issuedCredential: IssuedCredential,
        issuanceRequest: IssuanceRequest,
        credentialConfiguration: CredentialConfiguration,
        onEvent: OpenId4VciManager.OnResult<IssueEvent>,
        addedDocuments: MutableSet<DocumentId>
    ) {
        when (issuedCredential) {
            is IssuedCredential.Deferred -> onEvent(
                IssueEvent.DocumentFailed(
                    issuanceRequest,
                    Exception("Deferred credential not implemented yet"),
                )
            )

            is IssuedCredential.Issued -> {
                val addResult = when (credentialConfiguration) {
                    is MsoMdocCredential -> issuanceRequest.storeCredential(
                        Base64.getUrlDecoder().decode(issuedCredential.credential)
                    )

                    is SdJwtVcCredential -> issuanceRequest.storeCredential(
                        issuedCredential.credential.toByteArray(Charsets.UTF_8)
                    )

                    is SeTlvVcCredential -> issuanceRequest.storeCredential(
                        Base64.getUrlDecoder().decode(issuedCredential.credential)
                    )

                    else -> throw CredentialIssuanceError.UnsupportedCredentialFormat
                }
                when (addResult) {
                    is AddDocumentResult.Failure -> {
                        documentManager.deleteDocumentById(issuanceRequest.documentId)
                        onEvent(IssueEvent.DocumentFailed(issuanceRequest, addResult.throwable))
                    }

                    is AddDocumentResult.Success -> {
                        addedDocuments += addResult.documentId
                        onEvent(IssueEvent.DocumentIssued(issuanceRequest, addResult.documentId, issuedCredential.credential))
                    }
                }
            }
        }
    }

    private fun <R : OpenId4VciManager.OnResult<V>, V> R.wrap(executor: Executor?): OpenId4VciManager.OnResult<V> {
        return OpenId4VciManager.OnResult { result: V ->
            (executor ?: context.mainExecutor()).execute {
                this@wrap.onResult(result)
            }
        }
    }

    private fun <R : OpenId4VciManager.OnResult<V>, V> launch(
        onResult: R,
        block: suspend (coroutineScope: CoroutineScope, onResult: R) -> Unit
    ) {
        val scope = CoroutineScope(Dispatchers.IO)
        scope.launch { block(scope, onResult) }
    }

    private fun clearStateThen(block: () -> Unit) {
        suspendedAuthorization?.close()
        suspendedAuthorization = null
        block()
    }

    companion object {
        private const val TAG = "DefaultOpenId4VciManage"

        private fun OpenId4VciManager.Config.toOpenId4VCIConfig(context: Context, keyForIssuingAuthChannel: JWK?): OpenId4VCIConfig {
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
                        issuerId = CredentialIssuerId(issuerUrl).getOrThrow(),
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
}
