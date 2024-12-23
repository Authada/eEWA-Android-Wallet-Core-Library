/*
 * Copyright (c) 2023-2024 European Commission
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

package eu.europa.ec.eudi.wallet

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.ComponentActivity
import androidx.annotation.RawRes
import com.nimbusds.jose.jwk.JWK
import de.authada.eewa.wallet.PidLib
import eu.europa.ec.eudi.iso18013.transfer.*
import eu.europa.ec.eudi.iso18013.transfer.engagement.NfcEngagementService
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStore
import eu.europa.ec.eudi.iso18013.transfer.response.DeviceRequest
import eu.europa.ec.eudi.iso18013.transfer.response.DeviceResponse
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseGenerator
import eu.europa.ec.eudi.iso18013.transfer.retrieval.BleRetrievalMethod
import eu.europa.ec.eudi.wallet.document.*
import eu.europa.ec.eudi.wallet.document.sample.LoadSampleResult
import eu.europa.ec.eudi.wallet.document.sample.SampleDocumentManager
import eu.europa.ec.eudi.wallet.internal.getCertificate
import eu.europa.ec.eudi.wallet.internal.mainExecutor
import eu.europa.ec.eudi.wallet.issue.openid4vci.*
import eu.europa.ec.eudi.wallet.transfer.FormatDocRequest
import eu.europa.ec.eudi.wallet.transfer.FormatDocumentsResolver
import eu.europa.ec.eudi.wallet.transfer.FormatRequestDocument
import eu.europa.ec.eudi.wallet.transfer.asMdocDocumentsResolver
import eu.europa.ec.eudi.wallet.transfer.openid4vp.OpenId4VpResponse
import eu.europa.ec.eudi.wallet.transfer.openid4vp.OpenId4VpResponseGeneratorImpl
import eu.europa.ec.eudi.wallet.transfer.openid4vp.OpenId4vpManager
import eu.europa.ec.eudi.wallet.util.DefaultNfcEngagementService
import java.security.cert.X509Certificate
import java.util.concurrent.Executor

/**
 * Eudi wallet sdk object to access the sdk functionalities. This object must be initialized before
 * using the sdk. The initialization can be done in the application class. The sdk can be initialized
 * with a [EudiWalletConfig] object.
 *
 * Initialize the sdk:
 * ```
 * val config = EudiWalletConfig.Builder(appContext)
 *    .storageDir(appContext.filesDir)
 *    .encryptDocumentsInStorage(true)
 *    .useHardwareToStoreKeys(true)
 *    .userAuthenticationRequired(true)
 *    .userAuthenticationTimeOut(30_000L)
 *    .trustedReaderCertificates(listof<X509Certificate>(
 *      // add trusted reader certificates
 *    ))
 *    .bleTransferMode(EudiWalletConfig.BLE_SERVER_PERIPHERAL_MODE)
 *    .build()
 * EudiWallet.init(context, config)
 * ```
 * @see [EudiWalletConfig] on how to configure the sdk
 *
 *
 *
 */
@SuppressLint("StaticFieldLeak")
object EudiWallet {

    @Volatile
    private lateinit var context: Context
    private lateinit var _config: EudiWalletConfig
    private var transferMode: TransferMode? = null

    var secureElementPidLib: PidLib? = null

    /**
     * Initialize the sdk with the given [config]
     *
     * @param context application context
     * @param config configuration object
     */
    fun init(context: Context, config: EudiWalletConfig) {
        this.context = context.applicationContext
        this._config = config
    }

    /**
     * The Config that used to initialize the sdk
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     */
    val config get() = requireInit { _config }

    /**
     * Document manager
     * @see [DocumentManager]
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     */
    val documentManager: SampleDocumentManager by lazy {
        requireInit {
            val delegate = DocumentManager.Builder(context)
                .apply {
                    storageDir = config.documentsStorageDir
                    useEncryption = config.encryptDocumentsInStorage
                    checkPublicKeyBeforeAdding = config.verifyMsoPublicKey
                    secureElementPidLib = this@EudiWallet.secureElementPidLib
                    secureArea = this@EudiWallet.secureElementPidLib?.let {pidLib ->
                        {
                            SecureElementSecureArea(pidLib, it)
                        }
                    }
                }
                .build() as DocumentManagerImpl

            delegate.userAuth(config.userAuthenticationRequired)
                .userAuthTimeout(config.userAuthenticationTimeOut)

            SampleDocumentManager.Builder(context)
                .apply { documentManager = delegate }
                .hardwareBacked(config.useHardwareToStoreKeys)
                .build()
        }
    }

    /**
     * Transfer manager
     * @see [TransferManager]
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     */
    internal val transferManager: TransferManager by lazy {
        requireInit {
            TransferManager.Builder(context)
                .apply {
                    retrievalMethods = deviceRetrievalMethods
                    responseGenerator = deviceResponseGenerator
                }
                .build()
        }
    }

    /**
     * OpenId4VP manager that can be used to verify OpenId4Vp requests
     * @see [OpenId4vpManager]
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     * or if the [EudiWalletConfig.openId4VPConfig] is not set
     */
    private val openId4vpManager: OpenId4vpManager? by lazy {
        requireInit {
            config.openId4VPConfig?.let { openId4VpConfig ->
                OpenId4vpManager(
                    context,
                    openId4VpConfig,
                    openId4VpResponseGenerator
                ).apply {
                    _config.trustedReaderCertificates?.let {
                        setReaderTrustStore(ReaderTrustStore.getDefault(it))
                    }
                }
            }
        }
    }

    /**
     * Returns the list of documents
     * @see [DocumentManager.getDocumentsSynchronous]
     * @return the list of documents
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     */
    fun getDocuments(): List<Document> = documentManager.getDocumentsSynchronous()

    /**
     * Returns the list of documents
     * @see [DocumentManager.getDocumentsSynchronous]
     * @return the list of documents
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     */
    suspend fun getDocumentsWithMetaData(): List<Document> =
        documentManager.getDocumentsWithMetaData()

    /**
     * Returns the document with the given [documentId]
     * @param documentId the document's id
     * @see [DocumentManager.getDocumentById]
     * @return the document with the given [documentId] or null if not found
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     */
    suspend fun getDocumentById(documentId: DocumentId): Document? =
        documentManager.getDocumentById(documentId)

    /**
     * Delete the document with the given [documentId]
     * @param documentId the document's id
     * @see [DocumentManager.deleteDocumentById]
     * @return [DeleteDocumentResult]
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     */
    suspend fun deleteDocumentById(documentId: DocumentId): DeleteDocumentResult =
        documentManager.deleteDocumentById(documentId)

    /**
     * Create an issuance request for the given [docType]
     * @param docType the docType of the document
     * @param format the format of the document
     * @param hardwareBacked flag that indicates if the document's keys should be stored in hardware or not
     * @param attestationChallenge the attestation challenge to be used for the document's keys
     * attestation (optional). If not provided, the sdk will generate a random challenge
     * @see [DocumentManager.createIssuanceRequest]
     * @return [CreateIssuanceRequestResult]
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     */
    fun createIssuanceRequest(
        docType: String,
        format: Format,
        hardwareBacked: Boolean,
        attestationChallenge: ByteArray? = null,
    ): CreateIssuanceRequestResult =
        documentManager.createIssuanceRequest(docType, format, hardwareBacked, attestationChallenge)

    private val openId4VciManager: OpenId4VciManager? by lazy {
        requireInit {
            config.openId4VciConfig?.let { config ->
                OpenId4VciManager(context) {
                    documentManager(this@EudiWallet.documentManager)
                    config(config)
                }
            }
        }
    }

    /**
     * Issue a document using the OpenId4VCI protocol
     * @param docType the document type to issue
     * @param txCode the transaction code for pre-authorized issuing
     * @param executor the executor defines the thread on which the callback will be called. If null, the callback will be called on the main thread
     * @param onEvent the callback to be called when the document is issued
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     * @throws IllegalStateException if [EudiWalletConfig.openId4VciConfig] is not set
     * @see [OpenId4VciManager.issueDocumentByDocType]
     * @see [OpenId4VciManager.OnIssueEvent] on how to handle the result
     * @see [IssueEvent.DocumentRequiresUserAuth] on how to handle user authentication
     */
    fun issueDocumentByDocTypeAndFormat(
        docType: String,
        txCode: String? = null,
        docItems: List<DocItem>? = null,
        formats: Set<CredentialFormat> = supportedFormats,
        executor: Executor? = null,
        onEvent: OpenId4VciManager.OnIssueEvent,
    ) {
        issueDocumentByDocTypeAndFormat(
            docType,
            txCode,
            docItems,
            formats,
            executor,
            onEvent,
            keyForIssuingAuthChannelThisMethod = null,
            storeDocument = true
        )
    }

    fun issueDocumentByDocTypeAndFormat(
        docType: String,
        txCode: String? = null,
        docItems: List<DocItem>? = null,
        formats: Set<CredentialFormat> = supportedFormats,
        executor: Executor? = null,
        onEvent: OpenId4VciManager.OnIssueEvent,
        keyForIssuingAuthChannelThisMethod: JWK? = null,
        storeDocument: Boolean = true
    ) {
        openId4VciManager?.issueDocumentByDocTypeAndSupportedFormats(
            docType,
            txCode,
            formats,
            executor,
            onEvent,
            claims = docItems,
            keyForIssuingAuthChannel = keyForIssuingAuthChannelThisMethod,
            storeDocument = storeDocument
        ) ?: run {
            (executor ?: context.mainExecutor()).execute {
                onEvent(IssueEvent.failure(IllegalStateException("OpenId4Vci config is not set in configuration")))
            }
        }
    }

    /**
     * Issue a document using an offer and the OpenId4VCI protocol
     * @param offer the offer to issue
     * @param txCode the transaction code for pre-authorized issuing
     * @param executor the executor defines the thread on which the callback will be called. If null, the callback will
     * be called on the main thread
     * @param onEvent the callback to be called when the document is issued
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     * @throws IllegalStateException if [EudiWalletConfig.openId4VciConfig] is not set
     * @see [OpenId4VciManager.issueDocumentByOffer]
     * @see [OpenId4VciManager.OnIssueEvent] on how to handle the result
     * @see [IssueEvent.DocumentRequiresUserAuth] on how to handle user authentication
     */
    fun issueDocumentByOffer(
        offer: Offer,
        txCode: String? = null,
        executor: Executor? = null,
        onEvent: OpenId4VciManager.OnIssueEvent
    ) {
        openId4VciManager?.issueDocumentByOffer(offer, txCode, executor, onEvent)
            ?: run {
                (executor ?: context.mainExecutor()).execute {
                    onEvent(IssueEvent.failure(IllegalStateException("OpenId4Vci config is not set in configuration")))
                }
            }
    }

    /**
     * Issue a document using an offerUri and the OpenId4VCI protocol
     * @param offerUri the offer uri
     * @param txCode the transaction code for pre-authorized issuing
     * @param executor the executor defines the thread on which the callback will be called. If null, the callback will be called on the main thread
     * @param onEvent the callback to be called when the document is issued
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     * @throws IllegalStateException if [EudiWalletConfig.openId4VciConfig] is not set
     * @see [OpenId4VciManager.issueDocumentByOfferUri]
     * @see [OpenId4VciManager.OnIssueEvent] on how to handle the result
     * @see [IssueEvent.DocumentRequiresUserAuth] on how to handle user authentication
     */
    fun issueDocumentByOfferUri(
        offerUri: String,
        txCode: String? = null,
        executor: Executor? = null,
        onEvent: OpenId4VciManager.OnIssueEvent
    ) {
        openId4VciManager?.issueDocumentByOfferUri(offerUri, txCode, executor, onEvent) ?: run {
            (executor ?: context.mainExecutor()).execute {
                onEvent(IssueEvent.failure(IllegalStateException("OpenId4Vci config is not set in configuration")))
            }
        }
    }

    /**
     * Resolves a document offer using OpenId4VCI protocol
     * @param offerUri the offer uri
     * @param executor the executor defines the thread on which the callback will be called. If null, the callback will be called on the main thread
     * @param onResult the callback to be called when the offer is resolved
     *
     * @see [OpenId4VciManager.OnResolvedOffer] on how to handle the result
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     * @throws IllegalStateException if [EudiWalletConfig.openId4VciConfig] is not set
     */
    fun resolveDocumentOffer(
        offerUri: String,
        executor: Executor? = null,
        onResult: OpenId4VciManager.OnResolvedOffer
    ) {
        openId4VciManager?.resolveDocumentOffer(offerUri, executor, onResult) ?: run {
            (executor ?: context.mainExecutor()).execute {
                onResult(OfferResult.Failure(IllegalStateException("OpenId4Vci config is not set in configuration")))
            }
        }
    }

    /**
     * Resumes the OpenId4VCI flow with the given [intent]
     * @param intent the intent that contains the authorization code
     * @throws [IllegalStateException] if no authorization request to resume
     */
    fun resumeOpenId4VciWithAuthorization(intent: Intent) {
        openId4VciManager?.resumeWithAuthorization(intent)
            ?: throw IllegalStateException("No OpenId4VciManager to resume")
    }

    /**
     * Resumes the OpenId4VCI flow with the given [intent]
     * @param uri the uri that contains the authorization code
     * @throws [IllegalStateException] if no authorization request to resume
     */
    fun resumeOpenId4VciWithAuthorization(uri: String) {
        openId4VciManager?.resumeWithAuthorization(uri)
            ?: throw IllegalStateException("No OpenId4VciManager to resume")
    }

    /**
     * Resumes the OpenId4VCI flow with the given [intent]
     * @param uri the uri that contains the authorization code
     * @throws [IllegalStateException] if no authorization request to resume
     */
    fun resumeOpenId4VciWithAuthorization(uri: Uri) {
        openId4VciManager?.resumeWithAuthorization(uri)
            ?: throw IllegalStateException("No OpenId4VciManager to resume")
    }

    /**
     * Loads sample data into the wallet's document manager
     * @param sampleData the sample data
     * @see [SampleDocumentManager.loadSampleData]
     * @return [AddDocumentResult]
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     */
    fun loadSampleData(sampleData: ByteArray): LoadSampleResult =
        documentManager.loadSampleData(sampleData)

    /**
     * Sets the reader trust store with the readers' certificates that are trusted by the wallet
     * @param readerTrustStore the reader trust store
     * @see [TransferManager.setReaderTrustStore]
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     * @return [EudiWallet]
     */
    fun setReaderTrustStore(readerTrustStore: ReaderTrustStore): EudiWallet {
        deviceResponseGenerator.setReaderTrustStore(readerTrustStore)
        openId4VpResponseGenerator.setReaderTrustStore(readerTrustStore)
        return this
    }

    /**
     * Sets the readers' certificates that are trusted by the wallet
     * @param trustedReaderCertificates list of trusted reader certificates
     * @see [TransferManager.setReaderTrustStore]
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     * @return [EudiWallet]
     */
    fun setTrustedReaderCertificates(trustedReaderCertificates: List<X509Certificate>) = apply {
        deviceResponseGenerator.setReaderTrustStore(
            ReaderTrustStore.getDefault(
                trustedReaderCertificates
            )
        )
        openId4VpResponseGenerator.setReaderTrustStore(
            ReaderTrustStore.getDefault(
                trustedReaderCertificates
            )
        )
    }

    /**
     * Sets the readers' certificates from raw resources that are trusted by the wallet
     * @param rawRes list of raw resources of trusted reader certificates
     * @see [TransferManager.setReaderTrustStore]
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     * @return [EudiWallet]
     */
    fun setTrustedReaderCertificates(@RawRes vararg rawRes: Int) = apply {
        setTrustedReaderCertificates(rawRes.map { context.getCertificate(it) })
    }

    /**
     * Adds a transfer event listener in order to be notified about transfer events
     * @see [TransferManager.addTransferEventListener]
     * @see [TransferEvent.Listener]
     * @param listener
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     * @return [EudiWallet]
     */
    fun addTransferEventListener(listener: TransferEvent.Listener) = apply {
        transferManager.addTransferEventListener(listener)
        openId4vpManager?.addTransferEventListener(listener)
    }

    /**
     * Removes a transfer event listener.
     * @see [TransferManager.removeTransferEventListener]
     * @see [TransferEvent.Listener]
     * @param listener
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     * @return [EudiWallet]
     *
     */
    fun removeTransferEventListener(listener: TransferEvent.Listener) = apply {
        transferManager.removeTransferEventListener(listener)
        openId4vpManager?.removeTransferEventListener(listener)
    }

    /**
     * Removes all transfer event listeners.
     * @see [TransferManager.removeTransferEventListener]
     * @see [TransferEvent.Listener]
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     * @return [EudiWallet]
     */
    fun removeAllTransferEventListeners() = apply {
        transferManager.removeAllTransferEventListeners()
        openId4vpManager?.removeAllTransferEventListeners()
    }

    /**
     * Starts the transfer process by engaging with the reader via QR code
     * @see [TransferManager.startQrEngagement]
     * @throws IllegalStateException if [EudiWallet] is not firstly initialized via the [init] method
     */
    fun startQrEngagement() {
        transferMode = TransferMode.ISO_18013_5
        transferManager.startQrEngagement()
    }

    /**
     * Enables the NFC engagement functionality
     * You must also add [DefaultNfcEngagementService] to your application's manifest file
     * @param activity
     */
    fun enableNFCEngagement(activity: ComponentActivity) {
        transferMode = TransferMode.ISO_18013_5
        NfcEngagementService.enable(activity, DefaultNfcEngagementService::class.java)
    }

    /**
     * Disables the NFC engagement functionality
     * @param activity
     */
    fun disableNFCEngagement(activity: ComponentActivity) {
        NfcEngagementService.disable(activity)
    }

    /**
     * Start engagement from an Intent.
     * This will perform engagement for REST API or OpenId4Vp depending on the scheme.
     * @param intent Intent
     */
    fun startEngagementFromIntent(intent: Intent) {
        requireInit {
            when (intent.scheme) {
                "mdoc" -> {
                    transferMode = TransferMode.REST_API
                    transferManager.startEngagementToApp(intent)
                }

                _config.openId4VPConfig?.scheme -> { // openid4vp scheme
                    transferMode = TransferMode.OPENID4VP
                    openId4vpManager?.resolveRequestUri(intent.toUri(0))
                }

                else -> throw IllegalStateException("Not supported scheme")
            }
        }
    }

    /**
     * Start engagement for REST API
     * @param intent Intent
     */
    fun startEngagementToApp(intent: Intent) {
        when (intent.scheme) {
            "mdoc" -> {
                transferMode = TransferMode.REST_API
                transferManager.startEngagementToApp(intent)
            }

            else -> throw IllegalStateException("Not supported scheme for REST API")
        }
    }

    /**
     * Start engagement for OpenId4Vp
     * @param openid4VpURI
     */
    fun resolveRequestUri(openid4VpURI: String) {
        requireInit {
            when (Uri.parse(openid4VpURI).scheme) {
                _config.openId4VPConfig?.scheme -> { // openid4vp scheme
                    transferMode = TransferMode.OPENID4VP
                    openId4vpManager?.resolveRequestUri(openid4VpURI)
                }

                else -> throw IllegalStateException("Not supported scheme for OpenId4Vp")
            }
        }
    }

    /**
     * Send a response by giving [DisclosedDocuments], i.e. the list of documents to be disclosed.
     * The method returns a `ResponseResult` object, which can be one of the following:
     *
     * 1. `ResponseResult.Failure`: The response creation failed. The error can be retrieved from
     * `responseResult.error`.
     * 2. `ResponseResult.Success`: The response was created successfully. The response can be
     * retrieved from `responseResult.response`.
     * 3. `ResponseResult.UserAuthRequired`: The response creation requires user authentication.
     *
     * @param disclosedDocuments the list of documents to be disclosed in the response.
     * @return [ResponseResult] the result of the response
     */
    fun sendResponse(disclosedDocuments: DisclosedDocuments): ResponseResult {
        // create response
        val responseResult = when (transferMode) {
            TransferMode.OPENID4VP ->
                openId4vpManager?.responseGenerator?.createResponse(disclosedDocuments)
                    ?: ResponseResult.Failure(
                        Throwable("Openid4vpManager has not been initialized properly")
                    )

            TransferMode.ISO_18013_5, TransferMode.REST_API ->
                transferManager.responseGenerator.createResponse(disclosedDocuments)

            else -> ResponseResult.Failure(Throwable("Not supported transfer mode"))
        }

        // send response if success
        when (responseResult) {
            is ResponseResult.Success -> {
                when (transferMode) {
                    TransferMode.OPENID4VP ->
                        //TODO workaround as currently vptoken can only be one string and doesnt support multiple presentations
                        (responseResult.response as OpenId4VpResponse).resultItems.first().let {
                            openId4vpManager?.sendResponse(it)
                        }

                    TransferMode.ISO_18013_5, TransferMode.REST_API ->
                        transferManager.sendResponse((responseResult.response as DeviceResponse).deviceResponseBytes)

                    else -> ResponseResult.Failure(Throwable("Not supported transfer mode"))
                }
            }

            else -> {}
        }
        return responseResult
    }

    /**
     * Stops the transfer process
     *
     * @param sendSessionTerminationMessage
     * @param useTransportSpecificSessionTermination
     */
    fun stopPresentation(
        sendSessionTerminationMessage: Boolean = true,
        useTransportSpecificSessionTermination: Boolean = false,
    ) {
        transferManager.stopPresentation(
            sendSessionTerminationMessage,
            useTransportSpecificSessionTermination
        )
        openId4vpManager?.close()
        transferMode = null
    }

    private fun <T> requireInit(block: () -> T): T {
        if (!::context.isInitialized) {
            throw IllegalStateException("EudiWallet.init() must be called before using the SDK")
        }
        return block()
    }

    private val deviceRetrievalMethods
        get() = listOf(
            BleRetrievalMethod(
                peripheralServerMode = config.blePeripheralServerModeEnabled,
                centralClientMode = config.bleCentralClientModeEnabled,
                clearBleCache = config.bleClearCacheEnabled,
            )
        )

    private val transferManagerDocumentsResolver: FormatDocumentsResolver
        get() = FormatDocumentsResolver { req ->
            documentManager.getDocumentsSynchronous().filterDocumentsBasedOnRequest(req).map { doc ->
                FormatRequestDocument(
                    documentId = doc.id,
                    docType = doc.docType,
                    docName = doc.name,
                    userAuthentication = doc.requiresUserAuth,
                    docRequest = req,
                )
            }
        }

    private fun List<Document>.filterDocumentsBasedOnRequest(docRequest: FormatDocRequest): List<Document> {
        return this
            .filter { doc -> doc.format == docRequest.format }
            .filter { doc ->
                when (docRequest.format) {
                    Format.MSO_MDOC -> doc.docType == docRequest.docType
                    Format.SD_JWT_VC, Format.SE_TLV -> {
                        val allowedDocType = docRequest.requestItems.find {
                            it.elementIdentifier.equals(
                                "vct",
                                ignoreCase = true
                            )
                        }?.namespace ?: docRequest.docType
                        doc.docType == allowedDocType
                    }
                }
            }
    }

    private val deviceResponseGenerator: ResponseGenerator<DeviceRequest> by lazy {
        requireInit {
            ResponseGenerator.Builder(context)
                .apply {
                    _config.trustedReaderCertificates?.let {
                        readerTrustStore = ReaderTrustStore.getDefault(it)
                    }
                    documentsResolver = transferManagerDocumentsResolver.asMdocDocumentsResolver()
                }.build()
        }
    }

    private val openId4VpResponseGenerator: OpenId4VpResponseGeneratorImpl by lazy {
        requireInit {
            OpenId4VpResponseGeneratorImpl.Builder(context)
                .apply {
                    _config.trustedReaderCertificates?.let {
                        readerTrustStore = ReaderTrustStore.getDefault(it)
                    }
                    formatDocumentsResolver = transferManagerDocumentsResolver
                    documentManager = this@EudiWallet.documentManager
                    secureArea = secureElementPidLib?.let { pidLib ->
                        {
                            SecureElementSecureArea(pidLib, it)
                        }
                    }
                }.build()
        }
    }

    private enum class TransferMode {
        OPENID4VP,
        REST_API,
        ISO_18013_5
    }

    private val supportedFormats = setOf(
        CredentialFormat.SE_TLV_VC,
        CredentialFormat.MSO_MDOC,
        CredentialFormat.SD_JWT_VC
    )
}