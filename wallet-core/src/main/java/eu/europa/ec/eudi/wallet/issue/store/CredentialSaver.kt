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

package eu.europa.ec.eudi.wallet.issue.store

import eu.europa.ec.eudi.openid4vci.CredentialConfiguration
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError
import eu.europa.ec.eudi.openid4vci.IssuedCredential
import eu.europa.ec.eudi.openid4vci.MsoMdocCredential
import eu.europa.ec.eudi.openid4vci.SdJwtVcCredential
import eu.europa.ec.eudi.openid4vci.SeTlvVcCredential
import eu.europa.ec.eudi.wallet.document.AddDocumentResult
import eu.europa.ec.eudi.wallet.document.DocumentId
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.IssuanceRequest
import eu.europa.ec.eudi.wallet.issue.openid4vci.IssueEvent
import eu.europa.ec.eudi.wallet.issue.openid4vci.OpenId4VciManager
import eu.europa.ec.eudi.wallet.issue.openid4vci.toMetaData
import java.util.Base64

internal class CredentialSaver(
    private val documentManager: DocumentManager
) {

    suspend fun storeIssuedCredential(
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
                        credentialConfiguration.display.firstOrNull()?.toMetaData(
                            uniqueDocumentId = addResult.documentId,
                        )?.run {
                            documentManager.storeMetaDataForCredential(this)
                        }

                        addedDocuments += addResult.documentId

                        onEvent(
                            IssueEvent.DocumentIssued(
                                issuanceRequest,
                                addResult.documentId,
                                issuedCredential.credential,
                            )
                        )
                    }
                }
            }
        }
    }
}