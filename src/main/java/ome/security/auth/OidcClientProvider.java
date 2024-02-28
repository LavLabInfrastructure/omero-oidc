package ome.security.auth;

import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import ome.conditions.ApiUsageException;
import ome.logic.OidcImpl;
import ome.model.meta.Experimenter;
/* 
 * Allows use of deprecated resource owner password grant
 * (Particularly for CLI until proper code auth flow is implemented)
 */
public class OidcClientProvider extends ConfigurablePasswordProvider {

    final protected OidcImpl oidcUtil;

    public OidcClientProvider(PasswordUtil util, OidcImpl oidc) {
        super(util);
        this.oidcUtil = oidc;
    }

    public OidcClientProvider(PasswordUtil util, OidcImpl oidc, boolean ignoreUnknown) {
        super(util, ignoreUnknown);
        this.oidcUtil = oidc;
    }

    // cannot
    @Override
    public boolean hasPassword(String user) {
        return false;
    }

    @Override
    public Boolean checkPassword(String user, String password, boolean readOnly) {
        // guard statements
        if (!oidcUtil.getSetting()){
            return null;
        }
        if (password == null || password.equals("")){
            log.warn("Empty Password for user: "+user);
            loginAttempt(user, false);
            return false;
        }
        OAuth2AuthenticatedPrincipal principal = oidcUtil.attemptPasswordGrant(user, password);
        if (principal != null){
            Long id = util.userId(user);
            // create user if doesn't exist
            if (null == id){
                try {
                    if (readOnly){
                        throw new IllegalStateException("Cannot create user!");
                    }
                    Experimenter experimenter = oidcUtil.createUser(principal);
                    if (experimenter == null){
                        loginAttempt(user, false);
                        return false;
                    }
                } catch (ApiUsageException e){
                    log.info(String.format(
                        "Default choice on create user: %s (%s)", user ,e));
                }
            }
            loginAttempt(user, true);
            return true;

        }
        return super.checkPassword(user, password, readOnly);
    }
}
