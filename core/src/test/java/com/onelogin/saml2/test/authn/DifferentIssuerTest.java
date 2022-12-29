package com.onelogin.saml2.test.authn;

import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Util;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class DifferentIssuerTest {

    @Test
    public void readResponseWithDifferentIssuerInAssertionWithNoAdditionalIssuers_responseIsInvalid() throws Exception {

        String xml = Util.getFileAsString("data/responses/response_different_issuer_in_assertion.xml");
        Assert.assertNotNull(xml);

        Map<String,Object> settingsMap = new HashMap<>();
        // Skip checking the timestamps, otherwise the validation fails
        settingsMap.put(SettingsBuilder.SECURITY_VALIDATE_TIMESTAMPS,false);
        settingsMap.put(SettingsBuilder.SP_ENTITYID_PROPERTY_KEY, "https://jerry-test.apps.twxc.acme.com/plugins/servlet/samlsso");
        settingsMap.put(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY,"https://dnexternal.b2clogin.com/external.acme.com/B2C_1A_Test-InternalJiraSAML");

        SettingsBuilder settingsBuilder = new SettingsBuilder().fromValues(settingsMap);
        Saml2Settings settings = settingsBuilder.build();

        SamlResponse samlResponse = new SamlResponse(settings,
                "https://jerry-test.apps.twxc.acme.com/plugins/servlet/samlsso",
                xml, false);

        boolean valid = samlResponse.isValid(null,false);
        Assert.assertFalse(valid);
    }

    @Test
    public void readResponseWithDifferentIssuerInAssertionWithAdditionalIssuers_responseValid() throws Exception {

        String xml = Util.getFileAsString("data/responses/response_different_issuer_in_assertion.xml");
        Assert.assertNotNull(xml);

        Map<String,Object> settingsMap = new HashMap<>();
        // Skip checking the timestamps, otherwise the validation fails
        settingsMap.put(SettingsBuilder.SECURITY_VALIDATE_TIMESTAMPS,false);
        settingsMap.put(SettingsBuilder.SP_ENTITYID_PROPERTY_KEY, "https://jerry-test.apps.twxc.acme.com/plugins/servlet/samlsso");
        settingsMap.put(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY,"https://dnexternal.b2clogin.com/external.acme.com/B2C_1A_Test-InternalJiraSAML");
        settingsMap.put(SettingsBuilder.IDP_ACCEPTED_ISSUERS_PROPERTY_KEY,"https://acme.com,https://dnexternal.b2clogin.com/dnexternal.onmicrosoft.com/B2C_1A_Test-TrustFrameworkBase");

        SettingsBuilder settingsBuilder = new SettingsBuilder().fromValues(settingsMap);
        Saml2Settings settings = settingsBuilder.build();

        SamlResponse samlResponse = new SamlResponse(settings,
                "https://jerry-test.apps.twxc.acme.com/plugins/servlet/samlsso",
                xml, false);

        boolean valid = samlResponse.isValid(null,false);

        if(samlResponse.getValidationException() != null) {
            throw samlResponse.getValidationException();
        }
        Assert.assertTrue(valid);
    }
}

