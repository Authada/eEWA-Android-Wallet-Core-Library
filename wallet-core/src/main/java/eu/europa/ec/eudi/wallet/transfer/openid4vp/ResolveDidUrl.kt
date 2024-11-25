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

package eu.europa.ec.eudi.wallet.transfer.openid4vp

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import foundation.identity.did.DIDURL
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.erwinkok.multiformat.multibase.Multibase
import org.erwinkok.multiformat.multicodec.Multicodec
import org.erwinkok.multiformat.util.readUnsignedVarInt
import org.erwinkok.result.flatMap
import org.erwinkok.result.getOrThrow
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec


fun resolveDidUrl(value: String): JWK {
    val url = DIDURL.fromString(value)
    val method = url.did.methodName
    require(method == "key" || method == "jwk") { "Unsupported DID method '$method'" }

    val jwk = resolveDidUrl(url)
    return jwk
}

/**
 * Resolves a DID URL to a [JWK].
 *
 * Currently:
 *
 * * did:key
 * * did:jwk
 *
 * methods are supported.
 */
private fun resolveDidUrl(url: DIDURL): JWK =
    when (val method = url.did.methodName) {
        "key" -> resolveDidKey(url)
        "jwk" -> resolveDidJwk(url)
        else -> error("Unsupported DID method '$method'")
    }

private val supportedDidKeyTypes = setOf(
    Multicodec.SECP256K1_PUB,
    Multicodec.X25519_PUB,
    Multicodec.ED25519_PUB,
    Multicodec.P256_PUB,
    Multicodec.P384_PUB,
    Multicodec.P521_PUB,
    Multicodec.RSA_PUB,
)

private val expectedDidKeySizes = mapOf(
    Multicodec.SECP256K1_PUB to 33,
    Multicodec.X25519_PUB to 32,
    Multicodec.ED25519_PUB to 32,
    Multicodec.P256_PUB to 33,
    Multicodec.P384_PUB to 49,
)

private fun resolveDidKey(url: DIDURL): JWK {
    require(url.did.methodName == "key") {
        "Expected 'key' method. Got '${url.did.methodName}' instead."
    }
    require(url.did.methodSpecificId[0] == 'z') {
        "Expected 'z' multibase. Got '${url.did.methodSpecificId[0]}' instead."
    }
    require(url.fragment.isNullOrBlank()) {
        "Invalid fragment. Expected no fragment but got '${url.fragment}' instead."
    }

    val (type, key) =
        ByteArrayInputStream(
            Multibase.decode(url.did.methodSpecificId).getOrThrow()
        ).use { inputStream ->
            val type = inputStream.readUnsignedVarInt()
                .flatMap { Multicodec.codeToType(it.toInt()) }
                .getOrThrow()

            val key = inputStream.readBytes()
            type to key
        }

    require(type in supportedDidKeyTypes) {
        "Unsupported type '${type.typeName}'. Expected on of '${
            supportedDidKeyTypes.joinToString(
                separator = ", ",
                transform = { it.typeName },
            )
        }'."
    }

    expectedDidKeySizes[type]?.let { expectedKeySize ->
        require(expectedKeySize == key.size) {
            "Expected a key size of '$expectedKeySize' for type '${type.typeName}'. Got '${key.size}' instead."
        }
    }

    fun decodeOctetPublicKey(curve: Curve, publicKey: ByteArray): OctetKeyPair =
        OctetKeyPair.Builder(curve, Base64URL.encode(publicKey)).build()

    fun decodeEcPublicKey(curve: Curve, publicKey: ByteArray): ECKey {
        val spec = ECNamedCurveTable.getParameterSpec(curve.stdName)
        val point = spec.curve.decodePoint(publicKey)
        val keySpec = ECPublicKeySpec(point, spec)
        val factory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance())
        val ecPublicKey = factory.generatePublic(keySpec) as ECPublicKey
        return ECKey.Builder(curve, ecPublicKey).build()
    }

    fun decodeRsaPublicKey(encodedPublicKey: ByteArray): RSAKey {
        val ans1PublicKey = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(encodedPublicKey)
        val keySpec = RSAPublicKeySpec(ans1PublicKey.modulus, ans1PublicKey.publicExponent)
        val factory = KeyFactory.getInstance("RSA", BouncyCastleProviderSingleton.getInstance())
        val publicKey = factory.generatePublic(keySpec) as RSAPublicKey
        return RSAKey.Builder(publicKey).build()
    }

    return when (type) {
        Multicodec.SECP256K1_PUB -> decodeEcPublicKey(Curve.SECP256K1, key)
        Multicodec.X25519_PUB -> decodeOctetPublicKey(Curve.X25519, key)
        Multicodec.ED25519_PUB -> decodeOctetPublicKey(Curve.Ed25519, key)
        Multicodec.P256_PUB -> decodeEcPublicKey(Curve.P_256, key)
        Multicodec.P384_PUB -> decodeEcPublicKey(Curve.P_384, key)
        Multicodec.P521_PUB -> decodeEcPublicKey(Curve.P_521, key)
        Multicodec.RSA_PUB -> decodeRsaPublicKey(key)
        else -> error(
            "Unsupported type '${type.typeName}'. Expected on of '${
                supportedDidKeyTypes.joinToString(
                    separator = ", ",
                    transform = { it.typeName },
                )
            }'.",
        )
    }
}

private fun resolveDidJwk(url: DIDURL): JWK {
    require(url.did.methodName == "jwk") {
        "Expected 'key' method. Got '${url.did.methodName}' instead."
    }
    require(url.fragment == "0") {
        "Invalid fragment. Expected '0' but got '${url.fragment}' instead."
    }

    return JWK.parse(Base64URL.from(url.did.methodSpecificId).decodeToString())
        .also {
            require(!it.isPrivate) { "jwk cannot contain a private key" }
        }
}
