package grails.plugin.springsecurity.kerberos

import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import org.springframework.beans.factory.InitializingBean
import org.springframework.security.authentication.AccountStatusUserDetailsChecker
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsChecker
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken
import org.springframework.security.kerberos.authentication.KerberosTicketValidation
import org.springframework.security.kerberos.authentication.KerberosTicketValidator
import org.springframework.util.Assert

class KerberosTracedServiceAuthenticationProvider implements AuthenticationProvider, InitializingBean {

    def KerberosTicketValidator kerberosTicketValidator;
    def org.springframework.security.core.userdetails.UserDetailsService userDetailsService;
    private static final Log LOG = LogFactory.getLog(KerberosTracedServiceAuthenticationProvider.class);
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    public KerberosTracedServiceAuthenticationProvider() {
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        KerberosServiceRequestToken auth = (KerberosServiceRequestToken) authentication;
        byte[] token = auth.getToken();
        LOG.debug("Try to validate Kerberos Token");
        try {
            KerberosTicketValidation ticketValidation = this.kerberosTicketValidator.validateTicket(token);
            LOG.debug("Succesfully validated " + ticketValidation.username());
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(ticketValidation.username());
            this.userDetailsChecker.check(userDetails);
            this.additionalAuthenticationChecks(userDetails, auth);
            KerberosServiceRequestToken responseAuth = new KerberosServiceRequestToken(userDetails, ticketValidation, userDetails.getAuthorities(), token);
            responseAuth.setDetails(authentication.getDetails());
            return responseAuth;
        } catch (java.lang.Exception e) {
            e.printStackTrace()
            throw e;
        }
    }


    public boolean supports(Class<? extends Object> auth) {
        return KerberosServiceRequestToken.class.isAssignableFrom(auth);
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userDetailsService, "userDetailsService must be specified");
        Assert.notNull(this.kerberosTicketValidator, "ticketValidator must be specified");
    }

    public void setUserDetailsService(org.springframework.security.core.userdetails.UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public void setTicketValidator(KerberosTicketValidator ticketValidator) {
        this.kerberosTicketValidator = ticketValidator;
    }

    public void setKerberosTicketValidator(KerberosTicketValidator ticketValidator) {
        this.kerberosTicketValidator = ticketValidator;
    }

    public KerberosTicketValidator getTicketValidator() {
        return this.kerberosTicketValidator;
    }


    protected void additionalAuthenticationChecks(UserDetails userDetails, KerberosServiceRequestToken authentication) throws AuthenticationException {

    }

}
