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

package eu.europa.ec.eudi.wallet.transfer

import eu.europa.ec.eudi.iso18013.transfer.DocItem
import eu.europa.ec.eudi.iso18013.transfer.DocRequest
import eu.europa.ec.eudi.iso18013.transfer.DocumentsResolver
import eu.europa.ec.eudi.iso18013.transfer.ReaderAuth
import eu.europa.ec.eudi.iso18013.transfer.RequestDocument
import eu.europa.ec.eudi.wallet.document.Format

fun interface FormatDocumentsResolver {
    fun resolveDocuments(docRequest: FormatDocRequest): List<FormatRequestDocument>
}

fun FormatDocumentsResolver.asMdocDocumentsResolver(): DocumentsResolver = DocumentsResolver {
    return@DocumentsResolver this.resolveDocuments(
        FormatDocRequest(
            Format.MSO_MDOC,
            it.docType,
            it.requestItems,
            it.readerAuth
        )
    ).map {
        it.toTransferObject()
    }
}

data class FormatDocRequest(
    val format: Format,
    val docType: String,
    val requestItems: List<DocItem>,
    val readerAuth: ReaderAuth?
)

data class FormatRequestDocument(
    val documentId: String,
    val docType: String,
    val docName: String,
    val userAuthentication: Boolean,
    val docRequest: FormatDocRequest,
)

fun FormatDocRequest.toTransferObject(): DocRequest = DocRequest(
    docType, requestItems, readerAuth
)

fun FormatRequestDocument.toTransferObject(): RequestDocument = RequestDocument(
    documentId, docType, docName, userAuthentication, docRequest.toTransferObject()
)
