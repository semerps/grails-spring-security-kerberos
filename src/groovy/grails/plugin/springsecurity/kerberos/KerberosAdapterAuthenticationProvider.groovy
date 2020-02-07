package grails.plugin.springsecurity.kerberos

import grails.transaction.Transactional
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.kerberos.authentication.KerberosClient
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken

@Transactional
class KerberosAdapterAuthenticationProvider implements org.springframework.security.authentication.AuthenticationProvider  {

    private KerberosClient kerberosClient;
    private org.springframework.security.core.userdetails.UserDetailsService userDetailsService;

    public KerberosAdapterAuthenticationProvider() {
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof  UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken auth = (UsernamePasswordAuthenticationToken)authentication;
            String validatedUsername = this.kerberosClient.login(auth.getName(), auth.getCredentials().toString());
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(validatedUsername);
            KerberosServiceRequestToken output = new KerberosServiceRequestToken(userDetails, null, userDetails.getAuthorities());
            output.setDetails(authentication.getDetails());
            return output;
        } else if (authentication instanceof org.springframework.security.kerberos.authentication.KerberosServiceRequestToken){
            KerberosServiceRequestToken auth = (KerberosServiceRequestToken)authentication;
            String validatedUsername = this.kerberosClient.login(auth.getName(), auth.getCredentials().toString());
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(validatedUsername);
            KerberosServiceRequestToken output = new KerberosServiceRequestToken(userDetails, auth.getCredentials(), userDetails.getAuthorities());
            output.setDetails(authentication.getDetails());
            return output;
        } else {
            return null;
        }
    }


    public boolean supports(Class<? extends Object> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setKerberosClient(KerberosClient kerberosClient) {
        this.kerberosClient = kerberosClient;
    }

    public void setUserDetailsService(org.springframework.security.core.userdetails.UserDetailsService detailsService) {
        this.userDetailsService = detailsService;
    }

}
