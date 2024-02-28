package ome.api;

import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import ome.model.meta.Experimenter;
import ome.security.auth.OidcConfig.OmeClientRegistration;

public interface IOidc extends ServiceInterface{
    
    public boolean getSetting();

    public Experimenter createUser(OAuth2AuthenticatedPrincipal principal);

    public String getUsername(OAuth2AuthenticatedPrincipal principal);

    public OmeClientRegistration lookupIssuer(String issuer);
    /* 
     * Attempts logging in by checking issuer against repo then introspecting given token
     */
    public OAuth2AuthenticatedPrincipal validateToken(String issuer, String token);

    /* 
     * Attempting client authorization using username and password on each repo entry
     * then uses authorized client to get an access token to get convert to principal
     */
    public OAuth2AuthenticatedPrincipal attemptPasswordGrant(String user, String password);
}
