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

package eu.europa.ec.eudi.wallet.attestation

import android.util.Log
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.KtorHttpClientFactory
import io.ktor.client.call.body
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType.Application
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.http.appendPathSegments
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

internal class WalletBackendServerClient(
    private val url: HttpsUrl,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {

    /**
     * Method that submits a request to the wallet provider backend for getting a cnonce
     *
     * @return cnonce
     */
    suspend fun getCNonce(): Result<CNonceResponseTO> = runCatching {
        ktorHttpClientFactory().use { client ->
            val requestUrl: String = URLBuilder(url.value.toExternalForm()).apply {
                appendPathSegments("cnonce")
            }.buildString()
            val response = client.get(requestUrl) {
                accept(Application.Json)
            }
            if (response.status.isSuccess()) {
                response.body<CNonceResponseTO>()
            } else {
                throw RuntimeException() //TODO custom error
            }
        }
    }

    /**
     * Method that submits a request to wallet provider backend to request wallet attestation
     *
     * @param request The request for wallet attestion
     * @return wallet attestation
     */
    suspend fun placeAttestationRequest(
        request: WalletBackendAttestationRequest
    ): Result<WalletBackendAttestationResponse> = runCatching {
        ktorHttpClientFactory().use { client ->
            val requestUrl: String = URLBuilder(url.value.toExternalForm()).apply {
                appendPathSegments("attestation")
            }.buildString()
            val response = client.post(requestUrl) {
                contentType(Application.Json)
                accept(Application.Json)
                setBody(request)
            }
            if (response.status.isSuccess()) {
                val responseTo = response.body<WalletBackendAttestationResponseTO>()
                WalletBackendAttestationResponse(SignedJWT.parse(responseTo.attestation))
            } else {
                val message = if (response.status == HttpStatusCode.BadRequest) {
                    "Key attestation failed in backend: Device Authenticity could not be validated. Check device clock"
                } else {
                    "Unknown error during key attestation backend call"
                }
                Log.e(TAG, message)
                throw RuntimeException(message)
            }
        }
    }


    @Serializable
    internal data class WalletBackendAttestationResponseTO(
        val attestation: String
    )


    @Serializable
    internal data class CNonceResponseTO(
        @SerialName("c_nonce") val cNonce: String,
        @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long,
    )

    companion object {
        private const val TAG = "WalletBackendServerClient"
    }

}
