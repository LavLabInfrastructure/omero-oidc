package ome.security.auth;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.util.Assert;

import ome.conditions.ApiUsageException;
import ome.logic.OidcImpl;
import ome.model.meta.Experimenter;
/*
 * ! USERNAME IS ISSUER URI AND PASSWORD IS JWT ACCESS TOKEN !
 *   Allows use of oidc access tokens for authentication
 */
public class OidcTokenProvider extends ConfigurablePasswordProvider {

    final protected OidcImpl oidcUtil;

    public OidcTokenProvider(PasswordUtil util, OidcImpl oidc) {
        super(util);
        Assert.notNull(oidc, "OidcConfig not configured in XML!");
        this.oidcUtil = oidc;
    }

    public OidcTokenProvider(PasswordUtil util, OidcImpl oidc, boolean ignoreUnknown) {
        super(util, ignoreUnknown);
        Assert.notNull(oidc, "OidcConfig not configured in XML!");
        this.oidcUtil = oidc;
    }

    // cannot
    @Override
    public boolean hasPassword(String issuer) {
        return false;
    }

    @Override
    public Boolean checkPassword(String issuer, String token, boolean readOnly) {
        // guard statements
        if (!oidcUtil.getSetting()){
            return null;
        }

        if (token == null || token.equals("")){
            log.warn("Empty Password for user: " + issuer);
            loginAttempt(issuer, false);
            return false;
        }
        
        OAuth2AuthenticatedPrincipal principal = oidcUtil.validateToken(issuer, token);
        
        if (principal != null){
            String user = oidcUtil.getUsername(principal);
    
            if (user == null){ // create user if doesn't exist
                Long id = util.userId(user);
                if (null == id){
                    try {
                        if (readOnly){
                            throw new IllegalStateException("Cannot create user!");
                        }
                        Experimenter experimenter = oidcUtil.createUser(principal);
                        if (experimenter != null){
                            loginAttempt(experimenter.getOmeName(), true);
                            return true;
                        }
                    } catch (ApiUsageException e){
                        log.info(String.format(
                            "Default choice on create user: %s (%s)", user ,e));
                    }
                }
            }
            loginAttempt(issuer, true);
            return true;
        }
        return super.checkPassword(issuer, token, readOnly);
    }
}




