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
import eu.europa.ec.eudi.openid4vci.ClientId
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.issue.openid4vci.OpenId4VciManager.Config
import java.util.concurrent.Executor


typealias IssuerMap = Map<String, Config.Issuer>

/**
 * OpenId4VciManager is the main entry point to issue documents using the OpenId4Vci protocol
 * It provides methods to issue documents using a document type or an offer, and to resolve an offer
 * @see[OpenId4VciManager.Config] for the configuration options
 */
interface OpenId4VciManager {

    /**
     * Issue a document using a document type
     * @param docType the document type to issue
     * @param txCode the transaction code to use for pre-authorized issuing
     * @param supportedFormats set of supported formats for issuing
     * @param executor the executor defines the thread on which the callback will be called. If null, the callback will be called on the main thread
     * @param onIssueEvent the callback to be called when the document is issued
     * @param claims the list of fields user decided to share with the Verifier
     * @see[IssueEvent] on how to handle the result
     * @see[IssueEvent.DocumentRequiresUserAuth] on how to handle user authentication
     */
    fun issueDocumentByDocTypeAndSupportedFormats(
        docType: String,
        txCode: String? = null,
        supportedFormats: Set<CredentialFormat>,
        executor: Executor? = null,
        onIssueEvent: OnIssueEvent,
        claims: List<DocItem>? = null,
        keyForIssuingAuthChannel: JWK?,
        storeDocument: Boolean = true
    )

    /**
     * Issue a document using an offer
     * @param offer the offer to issue
     * @param txCode the transaction code to use for pre-authorized issuing
     * @param executor the executor defines the thread on which the callback will be called. If null, the callback will be called on the main thread
     * @param onIssueEvent the callback to be called when the document is issued. This callback may be called multiple times, each for every document in the offer
     *
     * @see[IssueEvent] on how to handle the result
     * @see[IssueEvent.DocumentRequiresUserAuth] on how to handle user authentication
     */
    fun issueDocumentByOffer(
        offer: Offer,
        txCode: String? = null,
        executor: Executor? = null,
        onIssueEvent: OnIssueEvent
    )

    /**
     * Issue a document using an offer URI
     * @param offerUri the offer URI
     * @param txCode the transaction code to use for pre-authorized issuing
     * @param executor the executor defines the thread on which the callback will be called. If null, the callback will be called on the main thread
     * @param onIssueEvent the callback to be called when the document is issued. This callback may be called multiple times, each for every document in the offer
     * @see[IssueEvent] on how to handle the result
     * @see[IssueEvent.DocumentRequiresUserAuth] on how to handle user authentication
     */
    fun issueDocumentByOfferUri(
        offerUri: String,
        txCode: String? = null,
        executor: Executor? = null,
        onIssueEvent: OnIssueEvent
    )

    /**
     * Resolve an offer using OpenId4Vci protocol
     *
     * @param offerUri the offer URI
     * @param executor the executor defines the thread on which the callback will be called. If null, the callback will be called on the main thread
     * @param onResolvedOffer the callback to be called when the offer is resolved
     *
     */
    fun resolveDocumentOffer(
        offerUri: String,
        executor: Executor? = null,
        onResolvedOffer: OnResolvedOffer
    )

    /**
     * Resume the authorization flow after the user has been redirected back to the app
     * @param intent the intent that contains the authorization code
     * @throws [IllegalStateException] if no authorization request to resume
     *
     */
    fun resumeWithAuthorization(intent: Intent)

    /**
     * Resume the authorization flow after the user has been redirected back to the app
     * @param uri the uri that contains the authorization code
     * @throws [IllegalStateException] if no authorization request to resume
     *
     */
    fun resumeWithAuthorization(uri: Uri)

    /**
     * Resume the authorization flow after the user has been redirected back to the app
     * @param uri the uri that contains the authorization code
     * @throws [IllegalStateException] if no authorization request to resume
     *
     */
    fun resumeWithAuthorization(uri: String)

    fun interface OnResult<T> {
        fun onResult(result: T)
        operator fun invoke(result: T) = onResult(result)
    }

    /**
     * Callback to be called when a document is issued
     */
    fun interface OnIssueEvent : OnResult<IssueEvent>

    /**
     * Callback to be called when an offer is resolved
     */
    fun interface OnResolvedOffer : OnResult<OfferResult>

    /**
     * Builder to create an instance of [OpenId4VciManager]
     * @param context the context
     * @property config the [Config] to use
     * @property documentManager the [DocumentManager] to use
     */
    class Builder(private val context: Context) {
        var config: Config? = null
        var documentManager: DocumentManager? = null

        /**
         * Set the [Config] to use
         */
        fun config(config: Config) = apply { this.config = config }

        /**
         * Set the [DocumentManager] to use
         */
        fun documentManager(documentManager: DocumentManager) =
            apply { this.documentManager = documentManager }

        /**
         * Build the [OpenId4VciManager]
         * @throws [IllegalStateException] if config or documentManager is not set
         */
        fun build(): OpenId4VciManager {
            checkNotNull(config) { "config is required" }
            checkNotNull(documentManager) { "documentManager is required" }
            return DefaultOpenId4VciManager(context, documentManager!!, config!!)
        }
    }

    companion object {
        /**
         * Create an instance of [OpenId4VciManager]
         */
        operator fun invoke(context: Context, block: Builder.() -> Unit) =
            Builder(context).apply(block).build()
    }

    /**
     * Configuration for the OpenId4Vci issuer
     * @property issuerMap map of URLs for issuer based on docType
     * @property authFlowRedirectionURI the redirection URI for the authorization flow
     * @property useStrongBoxIfSupported use StrongBox for document keys if supported
     * @property useDPoPIfSupported flag that if set will enable the use of DPoP JWT
     */
    data class Config(
        val clientId: ClientId,
        private val issuerMap: IssuerMap,
        val authFlowRedirectionURI: String,
        val useStrongBoxIfSupported: Boolean,
        val useDPoPIfSupported: Boolean,
        val walletProviderUrl: String? = null
    ) {

        data class Issuer(
            val issuerUrl: String,
        )


        /**
         * Builder to create an instance of [Config]
         * @property issuerMap map of DocType to Issuer URL and Client ID
         * @property authFlowRedirectionURI the redirection URI for the authorization flow
         * @property useStrongBoxIfSupported use StrongBox for document keys if supported
         * @property useDPoPIfSupported flag that if set will enable the use of DPoP JWT
         *
         */
        class Builder {
            private var clientId: ClientId? = null
            private var issuerMap: IssuerMap? = null
            private var walletProviderUrl: String? = null
            private var authFlowRedirectionURI: String? = null
            private var useStrongBoxIfSupported: Boolean = false
            private var useDPoPIfSupported: Boolean = false

            /**
             * Set the client id
             */
            fun clientId(clientId: ClientId) =
                apply { this.clientId = clientId }

            /**
             * Set the issuer url
             */
            fun issuerMap(issuerMap: IssuerMap) =
                apply { this.issuerMap = issuerMap }

            /**
             * Set the redirection URI for the authorization flow
             */
            fun authFlowRedirectionURI(authFlowRedirectionURI: String) =
                apply { this.authFlowRedirectionURI = authFlowRedirectionURI }

            /**
             * Set the flag that if set will enable the use of StrongBox for document keys if supported
             */
            fun useStrongBoxIfSupported(useStrongBoxIfSupported: Boolean) =
                apply { this.useStrongBoxIfSupported = useStrongBoxIfSupported }

            /**
             * Set the flag that if set will enable the use of DPoP JWT
             */
            fun useDPoP(useDPoP: Boolean) = apply { this.useDPoPIfSupported = useDPoP }

            /**
             * Set the flag that if set will enable the use of client attestation
             */
            fun useClientAttestation(walletProviderUrl: String) =
                apply { this.walletProviderUrl = walletProviderUrl }

            /**
             * Build the [Config]
             * @throws [IllegalStateException] if issuerUrl, clientId or authFlowRedirectionURI is not set
             */
            fun build(): Config {
                return Config(
                    clientId = requireNotNull(clientId) { "clientId is required" },
                    issuerMap = requireNotNull(issuerMap) { "issuerMap is required" },
                    authFlowRedirectionURI = requireNotNull(authFlowRedirectionURI) { "authFlowRedirectionURI is required" },
                    useStrongBoxIfSupported = useStrongBoxIfSupported,
                    useDPoPIfSupported = useDPoPIfSupported,
                    walletProviderUrl = walletProviderUrl
                )
            }

            fun withAuthFlowRedirectionURI(authFlowRedirectionURI: String) =
                authFlowRedirectionURI(authFlowRedirectionURI)
        }

        fun getIssuerUrlByDocType(docType: String): String =
            issuerMap.getValue(docType).issuerUrl

        companion object {
            /**
             * Create an instance of [Config]
             */
            operator fun invoke(block: Builder.() -> Unit) = Builder().apply(block).build()

            private const val TAG = "OpenId4VciManager"
        }
    }
}