package ome.logic;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;

import ome.api.IOidc;
import ome.api.ServiceInterface;
import ome.conditions.ValidationException;
import ome.model.meta.Experimenter;
import ome.model.meta.ExperimenterGroup;
import ome.security.auth.OidcConfig;
import ome.security.auth.RoleProvider;
import ome.security.auth.OidcConfig.OmeClientRegistration;
import ome.services.util.ReadOnlyStatus;
import ome.system.OmeroContext;
import ome.system.Roles;

public class OidcImpl extends AbstractLevel2Service implements IOidc,
        ApplicationContextAware {
    private final RoleProvider provider;

    private final OidcConfig config;

    private final Roles roles;

    private OmeroContext appContext;

    public OidcImpl(Roles roles, OidcConfig config, 
            RoleProvider roleProvider) {
        this.roles = roles;
        this.config = config;
        this.provider = roleProvider;

        // if no readOnlyStatus ( Likely means missing omero-context )
        // turn on readonlystatus ( Primarily for unit tests )
        if (readOnlyStatus == null){
            readOnlyStatus = new ReadOnlyStatus (true, true);
        }
    }
    public void setApplicationContext(ApplicationContext arg0)
            throws BeansException {
        appContext = (OmeroContext) arg0;
    }
    public Class<? extends ServiceInterface> getServiceInterface() {
        return IOidc.class;
    }

    public boolean getSetting(){
        return config.isEnabled(); //testing
    }

    public Experimenter createUser(OAuth2AuthenticatedPrincipal principal){
        if (!readOnlyStatus.isReadOnlyDb()){
            String username = getUsername(principal);
            if (provider.isIgnoreCaseLookup()) {
                username = username.toLowerCase();
            }
            if (iQuery.findByString(Experimenter.class, "omeName", username) != null) {
                throw new ValidationException("User already exists: " + username);
            }
            Experimenter exp = new Experimenter();
            exp.setOmeName(username);

            long uid = provider.createExperimenter(exp, new ExperimenterGroup(roles.getSystemGroupId(), false));

            return iQuery.get(Experimenter.class, uid);
        }
        return null;
    }
    public String getUsername(OAuth2AuthenticatedPrincipal principal){
        return principal.getAttribute(OidcConfig.DefaultOmeOidcMap.OME_NAME);
    }

    public OmeClientRegistration lookupIssuer(String issuer){
        return config.lookupIssuer(issuer);
    }
    /* 
     * Attempts logging in by checking issuer against repo then introspecting given token
     */
    public OAuth2AuthenticatedPrincipal validateToken(String issuer, String token){
        OmeClientRegistration reg = config.lookupIssuer(issuer);
        reg.clientProvider.authorize(OAuth2AuthorizationContext
            .withClientRegistration(reg.registration)
            .principal(
                new BearerTokenAuthenticationToken(token))
            .build());
        return reg.introspector.introspect(token);
        // return reg.introspector.introspect(reg.decoder.decode(token).toString());
    }

    /* 
     * Attempting client authorization using username and password on each repo entry
     * then uses authorized client to get an access token to get convert to principal
     */
    public OAuth2AuthenticatedPrincipal attemptPasswordGrant(String user, String password){
        if(config.isPasswordGrantEnabled()) {
            for (String issuer : config.getAllIssuers()){
                OmeClientRegistration reg = config.lookupIssuer(issuer);
                Authentication auth = new UsernamePasswordAuthenticationToken(user, password);
                OAuth2AuthorizationContext oac = OAuth2AuthorizationContext.withClientRegistration(reg.registration)
	    		    .principal(auth)
	    		    .attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, user)
	    		    .attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password)
	    		    .build();
                OAuth2AuthorizedClient authorizedClient = reg.clientProvider.authorize(oac);
                System.out.println(authorizedClient);
                if(authorizedClient != null){
                    return validateToken(issuer, authorizedClient.getAccessToken().getTokenValue());
                } 
            }
        }
        return null;
    }
}