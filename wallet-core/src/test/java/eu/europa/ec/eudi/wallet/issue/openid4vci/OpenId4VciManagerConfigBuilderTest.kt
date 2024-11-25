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

import eu.europa.ec.eudi.wallet.document.Constants.EU_PID_DOCTYPE
import eu.europa.ec.eudi.wallet.document.Constants.MDL_DOCTYPE
import eu.europa.ec.eudi.wallet.documentsTest.util.DocType
import eu.europa.ec.eudi.wallet.internal.CLIENT_ID
import org.junit.Assert.*
import org.junit.Test

class OpenId4VciManagerConfigBuilderTest {

    @Test
    fun `ConfigBuilder builds Config with valid issuerMap, and authFlowRedirectionURI`() {
        val builder = OpenId4VciManager.Config.Builder()
            .issuerMap(VALID_ISSUER_URLS_PROVIDER)
            .clientId(CLIENT_ID)
            .withAuthFlowRedirectionURI("app://redirect")

        val config = builder.build()

        assertNotNull(config)
    }

    @Test
    fun `ConfigBuilder throws exception when issuerMap is not set`() {
        val builder = OpenId4VciManager.Config.Builder()
            .authFlowRedirectionURI("app://redirect")

        assertThrows(IllegalArgumentException::class.java) {
            builder.build()
        }
    }

    @Test
    fun `ConfigBuilder throws exception when authFlowRedirectionURI is not set`() {
        val builder = OpenId4VciManager.Config.Builder()
            .issuerMap(VALID_ISSUER_URLS_PROVIDER)

        assertThrows(IllegalArgumentException::class.java) {
            builder.build()
        }
    }

    @Test
    fun `ConfigBuilder sets issuerUrl correctly`() {
        val builder = OpenId4VciManager.Config.Builder()
            .issuerMap(VALID_ISSUER_URLS_PROVIDER)
            .clientId(CLIENT_ID)
            .authFlowRedirectionURI("app://redirect")

        val config = builder.build()

        assertEquals(
            "https://issuer.example.com/mdl",
            config.getIssuerUrlByDocType(DocType.MDL.docTypeName)
        )
        assertEquals(CLIENT_ID, config.clientId)
        assertEquals(
            "https://issuer.example.com/pid",
            config.getIssuerUrlByDocType(DocType.PID.docTypeName)
        )
        assertEquals("app://redirect", config.authFlowRedirectionURI)
        assertFalse(config.useStrongBoxIfSupported)
        assertFalse(config.useDPoPIfSupported)
    }

    @Test
    fun `ConfigBuilder sets useStrongBoxIfSupported correctly`() {
        val builder = OpenId4VciManager.Config.Builder()
            .issuerMap(VALID_ISSUER_URLS_PROVIDER)
            .clientId(CLIENT_ID)
            .authFlowRedirectionURI("app://redirect")
            .useStrongBoxIfSupported(true)

        val config = builder.build()

        assertTrue(config.useStrongBoxIfSupported)
    }

    @Test
    fun `ConfigBuilder sets useDPoPIfSupported correctly`() {
        val builder = OpenId4VciManager.Config.Builder()
            .issuerMap(VALID_ISSUER_URLS_PROVIDER)
            .clientId(CLIENT_ID)
            .authFlowRedirectionURI("app://redirect")
            .useDPoP(true)

        val config = builder.build()

        assertTrue(config.useDPoPIfSupported)
    }

    companion object {
        private val VALID_ISSUER_URLS_PROVIDER: IssuerMap = mapOf(
            EU_PID_DOCTYPE to OpenId4VciManager.Config.Issuer(
                "https://issuer.example.com/pid",
            ),
            MDL_DOCTYPE to OpenId4VciManager.Config.Issuer(
                "https://issuer.example.com/mdl"
            )
        )
    }
}