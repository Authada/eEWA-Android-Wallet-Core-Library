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

import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.ProofType
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.serializer

@OptIn(ExperimentalSerializationApi::class)
internal object ProofSerializer : KSerializer<Proof> {
    @Serializable
    data class ProofJson(
        @SerialName("proof_type") val proofType: String,
        @SerialName("jwt") val jwt: String? = null,
    )

    private val internal = serializer<ProofJson>()
    override val descriptor: SerialDescriptor = SerialDescriptor("Proof", internal.descriptor)

    override fun deserialize(decoder: Decoder): Proof {
        val deserialized = internal.deserialize(decoder)
        return when (deserialized.proofType) {
            ProofType.JWT.toString().lowercase() -> {
                deserialized.jwt?.let {
                    Proof.Jwt(SignedJWT.parse(deserialized.jwt))
                } ?: error("Invalid JWT proof: missing 'jwt' attribute.")
            }
            else -> error("Unsupported proof type: ${deserialized.proofType}")
        }
    }

    override fun serialize(encoder: Encoder, value: Proof) {
        when (value) {
            is Proof.Jwt -> internal.serialize(
                encoder,
                ProofJson(
                    proofType = ProofType.JWT.toString().lowercase(),
                    jwt = value.jwt.serialize(),
                ),
            )

        }
    }
}
