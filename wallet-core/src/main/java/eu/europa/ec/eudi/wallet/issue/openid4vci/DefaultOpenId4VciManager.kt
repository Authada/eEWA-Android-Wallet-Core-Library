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
import android.content.Intent
import android.net.Uri
import android.util.Log
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.iso18013.transfer.DocItem
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.http.NamespaceForClaimsIfMdoc
import eu.europa.ec.eudi.wallet.document.DocumentId
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.IssuanceRequest
import eu.europa.ec.eudi.wallet.internal.mainExecutor
import eu.europa.ec.eudi.wallet.issue.openid4vci.IssueEvent.Companion.failure
import eu.europa.ec.eudi.wallet.issue.store.CredentialSaver
import kotlinx.coroutines.*
import net.minidev.json.JSONObject
import java.util.concurrent.Executor

internal class DefaultOpenId4VciManager(
    private val context: Context,
    private val documentManager: DocumentManager,
    var config: OpenId4VciManager.Config
) : OpenId4VciManager {

    private val issuerAuthorization: IssuerAuthorization by lazy {
        IssuerAuthorization(context)
    }
    private val offerUriCache = mutableMapOf<String, Offer>()

    private val credentialSaver: CredentialSaver by lazy {
        CredentialSaver(documentManager)
    }

    override fun issueDocumentByDocTypeAndSupportedFormats(
        docType: String,
        txCode: String?,
        supportedFormats: Set<CredentialFormat>,
        executor: Executor?,
        onIssueEvent: OpenId4VciManager.OnIssueEvent,
        claims: List<DocItem>?,
        keyForIssuingAuthChannel: JWK?,
        storeDocument: Boolean
    ) {
        val listener = onIssueEvent.wrap(executor)
        runBlocking {
            try {
                val credentialIssuerId =
                    CredentialIssuerId(config.getIssuerUrlByDocType(docType)).getOrThrow()
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
                    claims = mapClaimsToCredentialOffer(claims, supportedFormats)
                )

                val offer = DefaultOffer(credentialOffer, filterList)
                doIssueDocumentByOffer(
                    offer,
                    txCode,
                    config,
                    listener,
                    keyForIssuingAuthChannel,
                    storeDocument
                )

            } catch (e: Throwable) {
                Log.e(TAG, "error during issueDocumentByDocType", e)
                listener(failure(e))
            }
        }
    }


    private fun mapClaimsToCredentialOffer(
        claims: List<DocItem>?,
        supportedFormats: Set<CredentialFormat>
    ): Map<NamespaceForClaimsIfMdoc?, Any> {
        val claimsInMdocFormat = supportedFormats.any { it == CredentialFormat.MSO_MDOC }
        val userSelectedClaims: Map<NamespaceForClaimsIfMdoc?, Map<String, JSONObject>>? =
            if (claimsInMdocFormat) {
                claims?.groupBy { it.namespace }?.mapValues {
                    it.value.associate { docItem ->
                        docItem.elementIdentifier to JSONObject()
                    }
                }
            } else {
                val claimsWithoutNamespace = (claims?.map { docItem ->
                    docItem.elementIdentifier to JSONObject()
                }?.toMap())
                claimsWithoutNamespace?.let { mapOf(null to it) }
            }

        return userSelectedClaims ?: emptyMap()
    }

    override fun issueDocumentByOffer(
        offer: Offer,
        txCode: String?,
        executor: Executor?,
        onIssueEvent: OpenId4VciManager.OnIssueEvent
    ) {
        launch(onIssueEvent.wrap(executor)) { coroutineScope, listener ->
            try {
                doIssueDocumentByOffer(
                    offer,
                    txCode,
                    config,
                    listener,
                    keyForIssuingAuthChannel = null
                )
            } catch (e: Throwable) {
                listener(failure(e))
                coroutineScope.cancel("issueDocumentByOffer failed", e)
            }
        }
    }


    override fun issueDocumentByOfferUri(
        offerUri: String,
        txCode: String?,
        executor: Executor?,
        onIssueEvent: OpenId4VciManager.OnIssueEvent
    ) {
        launch(onIssueEvent.wrap(executor)) { coroutineScope, listener ->
            try {
                val offer = offerUriCache[offerUri]
                    ?: CredentialOfferRequestResolver().resolve(offerUri).getOrThrow()
                        .let { DefaultOffer(it) }
                doIssueDocumentByOffer(
                    offer,
                    txCode,
                    config,
                    listener,
                    keyForIssuingAuthChannel = null
                )
            } catch (e: Throwable) {
                listener(failure(e))
                coroutineScope.cancel("issueDocumentByOffer failed", e)
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
        issuerAuthorization.resumeFromIntent(intent)
    }

    override fun resumeWithAuthorization(uri: String) {
        resumeWithAuthorization(Uri.parse(uri))
    }

    override fun resumeWithAuthorization(uri: Uri) {
        issuerAuthorization.resumeFromUri(uri)
    }

    private suspend fun doIssueDocumentByOffer(
        offer: Offer,
        txCode: String?,
        config: OpenId4VciManager.Config,
        onEvent: OpenId4VciManager.OnResult<IssueEvent>,
        keyForIssuingAuthChannel: JWK?,
        storeDocument: Boolean = true
    ) {
        onEvent(IssueEvent.Started(offer.offeredDocuments.size))

        val addedDocuments = mutableSetOf<DocumentId>()

        val issuer = IssuerCreator().createIssuer(
            offer = offer,
            config = config,
            context = context,
            keyForIssuingAuthChannel = keyForIssuingAuthChannel,
            issuerIdentifier = offer.issuerIdentifier
        )

        with(issuer) {
            val authorizedRequest = issuerAuthorization.authorize(issuer, txCode)
            offer.offeredDocuments.forEach { item ->
                val issuanceRequest = documentManager
                    .createIssuanceRequest(
                        offerOfferedDocument = item,
                        hardwareBacked = config.useStrongBoxIfSupported,
                        storeDocument = storeDocument
                    )
                    .getOrThrow()

                val confIdentifier = (item as DefaultOfferedDocument).configurationIdentifier
                doIssueCredential(
                    authorizedRequest,
                    confIdentifier,
                    item.configuration,
                    issuanceRequest,
                    addedDocuments,
                    onEvent
                )
            }
            onEvent(IssueEvent.Finished(addedDocuments.toList()))
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

            is SubmittedRequest.Success -> credentialSaver.storeIssuedCredential(
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

                is SubmittedRequest.Success -> credentialSaver.storeIssuedCredential(
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
                        IssueEvent.DocumentRequiresUserAuth(
                            issuanceRequest,
                            status.cryptoObject
                        ) {
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

    companion object {
        private const val TAG = "DefaultOpenId4VciManage"
    }
}
